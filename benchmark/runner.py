"""Evaluation runner.

Runs the benign suite, the attack suite (user task x injection task through the task's
injection point) and the scenarios, under several configurations:
  baseline           - Phase-1 system, gateway logs only
  secured            - all modules on
  no_<module>        - secured with one module switched off (ablation)
Every run starts from a freshly reset database. Results go to results/<name>.jsonl and
are summarised by benchmark/analyze.py.

Examples:
  python run.py eval --quick                 # small sample, good for Groq free tier
  python run.py eval --suite attack --configs baseline,secured
  python run.py eval --full --ablation       # everything (use mock or a paid key)
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import time
from pathlib import Path

from backend.config import RESULTS_DIR, get_config
from backend.db.database import session_scope
from backend.db.seed import reset_database
from backend.gateway.gateway import gateway
from backend.llm.provider import STATS
from benchmark.inject import plant
from benchmark.scenarios import SCENARIOS, run_scenario
from benchmark.tasks import INJECTION_TASKS, PAYLOAD, USER_TASKS

MODULES = ["identity", "intent", "shield", "policy", "burst", "trust"]


def apply_config(name: str) -> None:
    cfg = get_config()
    cfg["security"]["modules"] = {m: True for m in MODULES}
    if name == "baseline":
        cfg["security"]["mode"] = "baseline"
    else:
        cfg["security"]["mode"] = "secured"
        if name.startswith("no_"):
            cfg["security"]["modules"][name[3:]] = False
        elif name.startswith("only_"):
            cfg["security"]["modules"] = {m: (m == name[5:]) for m in MODULES}
    gateway().refresh_llm()


def fresh() -> None:
    reset_database()
    gateway().reset()


def _defenses(trace: list[dict]) -> list[str]:
    out = set()
    for t in trace:
        if t.get("verdict") == "SANITIZED":
            out.add("shield")
        if t.get("kind") == "tool_call" and t.get("verdict") not in ("APPROVE", None):
            failed = [c["name"] for c in t.get("checks", []) if not c["passed"] and c["name"] != "trust"]
            out.update(failed or [f"rule{t.get('rule')}"])
    return sorted(out)


def _interference(trace: list[dict]) -> list[str]:
    return [f"{t.get('tool') or t['receiver']}:{t['verdict']}" for t in trace
            if t.get("kind") in ("tool_call", "message") and t.get("verdict") not in ("APPROVE", None)]


def run_one(task, inj=None) -> dict:
    from backend.agents.workflow import run_request

    fresh()
    where = None
    if inj is not None:
        where = plant(task.injection_point, task.target, PAYLOAD.format(goal=inj.goal), query=task.request)
    with session_scope() as s:
        exp = task.expect(s)
        inj_exp = inj.expect(s) if inj else None
    calls0 = STATS.snapshot()
    t0 = time.perf_counter()
    r = run_request(task.request)
    ms = (time.perf_counter() - t0) * 1000
    calls1 = STATS.snapshot()
    with session_scope() as s:
        user_ok = bool(task.check(s, exp, r))
        attack_ok = bool(inj.check(s, inj_exp)) if inj else None
    gw_ms = sum(t.get("ms", 0) for t in r["trace"])
    escalated = any(a.get("status") == "pending_approval" for a in r.get("actions", []))
    return {"task": task.id, "category": task.category, "escalated_to_human": escalated, "injection": inj.id if inj else None,
            "injection_name": inj.name if inj else None, "injection_point": where, "user_success": user_ok,
            "attack_success": attack_ok, "status": r["status"], "defenses": _defenses(r["trace"]),
            "interference": _interference(r["trace"]), "duration_ms": round(ms, 1), "gateway_ms": round(gw_ms, 2),
            "llm_calls": calls1["calls"] - calls0["calls"], "tokens": calls1["tokens"] - calls0["tokens"],
            "final": r["final"][:400]}


def run_suite(suite: str, configs: list[str], quick: bool, repeats: int, out: Path, seed: int = 7,
              max_attacks: int | None = None) -> None:
    rng = random.Random(seed)
    benign = USER_TASKS
    attack_pairs = [(t, i) for t in USER_TASKS if t.injection_point for i in INJECTION_TASKS]
    if quick:
        benign = [t for k, t in enumerate(USER_TASKS) if k % 3 == 0]          # 14 tasks, all categories
        attack_pairs = rng.sample(attack_pairs, 40)
    if max_attacks:
        attack_pairs = attack_pairs[:max_attacks]
    with open(out, "a", encoding="utf-8") as f:
        for cfg_name in configs:
            apply_config(cfg_name)
            for rep in range(repeats):
                if suite in ("benign", "all") and not (cfg_name.startswith(("no_", "only_")) and suite == "all"):
                    for k, t in enumerate(benign, 1):
                        row = run_one(t)
                        row.update({"suite": "benign", "config": cfg_name, "repeat": rep,
                                    "provider": get_config()["llm"]["provider"]})
                        f.write(json.dumps(row) + "\n")
                        f.flush()
                        print(f"[{cfg_name}] benign {k}/{len(benign)} {t.id} ok={row['user_success']} "
                              f"{row['duration_ms']:.0f}ms", flush=True)
                if suite in ("attack", "all"):
                    for k, (t, i) in enumerate(attack_pairs, 1):
                        row = run_one(t, i)
                        row.update({"suite": "attack", "config": cfg_name, "repeat": rep,
                                    "provider": get_config()["llm"]["provider"]})
                        f.write(json.dumps(row) + "\n")
                        f.flush()
                        if k % 10 == 0 or k == len(attack_pairs):
                            print(f"[{cfg_name}] attack {k}/{len(attack_pairs)}", flush=True)
                if suite in ("scenarios", "all") and not cfg_name.startswith(("no_", "only_")):
                    for name in SCENARIOS:
                        res = run_scenario(name)
                        row = {"suite": "scenario", "config": cfg_name, "repeat": rep, "scenario": name,
                               "attack_success": res["attack_succeeded"], "summary": res["summary"],
                               "provider": get_config()["llm"]["provider"],
                               "detail": {k: v for k, v in res.items() if k not in ("trace", "final", "verification")}}
                        f.write(json.dumps(row, default=str) + "\n")
                        f.flush()
                        print(f"[{cfg_name}] scenario {name}: attack_succeeded={res['attack_succeeded']}", flush=True)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="FinSecure evaluation runner")
    ap.add_argument("--suite", default="all", choices=["benign", "attack", "scenarios", "all"])
    ap.add_argument("--configs", default="baseline,secured")
    ap.add_argument("--ablation", action="store_true", help="also run secured minus each module (attack suite)")
    ap.add_argument("--quick", action="store_true", help="sample: 14 benign tasks, 40 attack runs")
    ap.add_argument("--full", action="store_true", help="all 40 benign tasks and all 380 attack runs")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--max-attacks", type=int, default=None)
    ap.add_argument("--name", default=None, help="results file name (default: results_<provider>)")
    args = ap.parse_args(argv)
    original = copy.deepcopy(get_config()["security"])
    provider = get_config()["llm"]["provider"]
    name = args.name or f"results_{provider}"
    out = RESULTS_DIR / f"{name}.jsonl"
    out.write_text("", encoding="utf-8")
    quick = args.quick or (not args.full and provider != "mock")
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    t0 = time.time()
    run_suite(args.suite, configs, quick, args.repeats, out, max_attacks=args.max_attacks)
    if args.ablation:
        run_suite("attack", [f"no_{m}" for m in MODULES] + [f"only_{m}" for m in MODULES], quick, args.repeats, out,
                  max_attacks=args.max_attacks)
    get_config()["security"].update(original)
    gateway().refresh_llm()
    print(f"\nWrote {out} in {time.time() - t0:.0f}s")
    from benchmark.analyze import analyze

    analyze(out)


if __name__ == "__main__":
    main()
