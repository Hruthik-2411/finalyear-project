"""Turn results/*.jsonl into results/summary.json, a markdown table and PNG charts."""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

from backend.config import RESULTS_DIR

SECURED_C, BASELINE_C = "#2a78d6", "#eb6834"      # categorical slots 1 and 2 (fixed: Secured, Baseline)
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def _pct(xs) -> float | None:
    xs = list(xs)
    return round(100 * sum(1 for x in xs if x) / len(xs), 1) if xs else None


def _p(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 1)


def summarize(rows: list[dict]) -> dict:
    by = defaultdict(list)
    for r in rows:
        by[(r["suite"], r["config"])].append(r)
    configs = sorted({r["config"] for r in rows}, key=lambda c: (c != "baseline", c != "secured", c))
    out = {"provider": rows[0].get("provider") if rows else None, "configs": {}, "by_goal": {}, "by_point": {},
           "scenarios": {}, "ablation": {}}
    for c in configs:
        ben, att = by[("benign", c)], by[("attack", c)]
        expected_escalation = {"unfreeze_account"}
        fp = [bool(r["interference"]) and r["category"] not in expected_escalation and
              any(":BLOCK" in i or ":ESCALATE" in i or ":RESTRICT" in i or ":ISOLATE" in i for i in r["interference"])
              for r in ben]
        dur = [r["duration_ms"] for r in ben + att]
        out["configs"][c] = {
            "benign_runs": len(ben), "attack_runs": len(att),
            "benign_utility": _pct(r["user_success"] for r in ben),
            "false_positive_rate": _pct(fp),
            "utility_under_attack": _pct(r["user_success"] for r in att),
            "utility_under_attack_with_human": _pct(r["user_success"] or r.get("escalated_to_human") for r in att),
            "attack_success_rate": _pct(r["attack_success"] for r in att),
            "latency_p50_ms": _p(dur, 0.5), "latency_p95_ms": _p(dur, 0.95),
            "gateway_ms_mean": round(statistics.mean([r["gateway_ms"] for r in ben + att]), 2) if dur else None,
            "llm_calls_mean": round(statistics.mean([r["llm_calls"] for r in ben + att]), 2) if dur else None,
        }
        if att:
            out["ablation"][c] = out["configs"][c]["attack_success_rate"]
        g, p = defaultdict(list), defaultdict(list)
        for r in att:
            g[r["injection_name"]].append(r["attack_success"])
            p[(r["injection_point"] or "").split(" ")[0] if r["injection_point"] else "none"].append(r["attack_success"])
        out["by_goal"][c] = {k: _pct(v) for k, v in sorted(g.items())}
        out["by_point"][c] = {k: _pct(v) for k, v in sorted(p.items())}
        defs = defaultdict(int)
        for r in att:
            for d in r["defenses"]:
                defs[d] += 1
        out["configs"][c]["defenses_triggered"] = dict(sorted(defs.items(), key=lambda x: -x[1]))
    for r in rows:
        if r["suite"] == "scenario":
            out["scenarios"].setdefault(r["scenario"], {})[r["config"]] = {
                "attack_success": r["attack_success"], "summary": r["summary"], "detail": r.get("detail", {})}
    return out


def markdown(summary: dict) -> str:
    lines = [f"# FinSecure evaluation results (provider: {summary['provider']})", "",
             "| Config | Benign utility % | False-positive % | Utility under attack % | ...incl. human approval % | Attack success % | p50 ms | p95 ms | LLM calls/run |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for c, v in summary["configs"].items():
        lines.append(f"| {c} | {v['benign_utility']} | {v['false_positive_rate']} | {v['utility_under_attack']} | "
                     f"{v['utility_under_attack_with_human']} | "
                     f"{v['attack_success_rate']} | {v['latency_p50_ms']} | {v['latency_p95_ms']} | {v['llm_calls_mean']} |")
    if summary["scenarios"]:
        lines += ["", "## Scenarios", "", "| Scenario | Baseline | Secured |", "| --- | --- | --- |"]
        for s, d in summary["scenarios"].items():
            b, sec = d.get("baseline", {}), d.get("secured", {})
            lines.append(f"| {s} | {b.get('summary', '-')} | {sec.get('summary', '-')} |")
    return "\n".join(lines) + "\n"


def charts(summary: dict, outdir: Path) -> list[str]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return []
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2,
                         "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True})
    files = []
    cfg = summary["configs"]
    if "baseline" in cfg and "secured" in cfg and summary["by_goal"].get("baseline"):
        goals = list(summary["by_goal"]["baseline"].keys())
        b = [summary["by_goal"]["baseline"].get(g) or 0 for g in goals]
        s = [summary["by_goal"]["secured"].get(g) or 0 for g in goals]
        fig, ax = plt.subplots(figsize=(9, 4.2))
        x = range(len(goals))
        ax.bar([i - 0.2 for i in x], s, 0.38, color=SECURED_C, label="Secured")
        ax.bar([i + 0.2 for i in x], b, 0.38, color=BASELINE_C, label="Baseline")
        ax.set_xticks(list(x), [g.replace("_", " ") for g in goals], rotation=30, ha="right")
        ax.set_ylabel("Attack success rate (%)")
        ax.set_ylim(0, 118)
        ax.set_yticks([0, 20, 40, 60, 80, 100])
        ax.set_title("Attack success by attacker goal", loc="left", color=INK, fontsize=12)
        ax.legend(frameon=False, loc="upper right")
        fig.tight_layout()
        p = outdir / "asr_by_goal.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        files.append(p.name)
        # utility / FPR / ASR overview
        metrics = [("benign_utility", "Benign utility"), ("utility_under_attack", "Utility under attack"),
                   ("attack_success_rate", "Attack success"), ("false_positive_rate", "False positives")]
        fig, ax = plt.subplots(figsize=(8, 3.8))
        x = range(len(metrics))
        sv = [cfg["secured"][m] or 0 for m, _ in metrics]
        bv = [cfg["baseline"][m] or 0 for m, _ in metrics]
        r1 = ax.bar([i - 0.2 for i in x], sv, 0.38, color=SECURED_C, label="Secured")
        r2 = ax.bar([i + 0.2 for i in x], bv, 0.38, color=BASELINE_C, label="Baseline")
        for rects in (r1, r2):
            for r in rects:
                ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 1.5, f"{r.get_height():.0f}%", ha="center",
                        fontsize=8.5, color=INK2)
        ax.set_xticks(list(x), [l for _, l in metrics])
        ax.set_ylim(0, 128)
        ax.set_yticks([0, 20, 40, 60, 80, 100])
        ax.set_ylabel("%")
        ax.set_title("Baseline vs secured", loc="left", color=INK, fontsize=12)
        ax.legend(frameon=False, loc="upper right", ncol=2)
        fig.tight_layout()
        p = outdir / "overview.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        files.append(p.name)
    abl = summary.get("ablation", {})
    if len(abl) > 2:
        names = list(abl.keys())
        fig, ax = plt.subplots(figsize=(10, 4.2))
        cols = [BASELINE_C if n == "baseline" else SECURED_C for n in names]
        bars = ax.bar(range(len(names)), [abl[n] or 0 for n in names], 0.6, color=cols)
        for r in bars:
            ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 1.5, f"{r.get_height():.1f}%", ha="center",
                    fontsize=8.5, color=INK2)
        ax.set_xticks(range(len(names)), [n.replace("no_", "without ").replace("only_", "only ") for n in names],
                      rotation=35, ha="right")
        ax.set_ylabel("Attack success rate (%)")
        ax.set_ylim(0, max([abl[n] or 0 for n in names] + [10]) * 1.18)
        ax.set_title("Ablation: attack success with one module removed / only one module on", loc="left", color=INK, fontsize=12)
        fig.tight_layout()
        p = outdir / "ablation.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        files.append(p.name)
    lau = summary.get("scenarios", {}).get("reputation_laundering", {}).get("secured", {}).get("detail", {})
    if lau.get("points"):
        pts = lau["points"]
        fig, ax = plt.subplots(figsize=(8, 3.8))
        t = [q["t_min"] for q in pts]
        ax.axhspan(0.7, 1.0, color="#f0efec", zorder=0)
        ax.axhline(0.7, color=INK2, lw=0.8, ls="--")
        ax.text(t[-1], 0.715, "auto-approve threshold 0.7", ha="right", fontsize=8.5, color=INK2)
        ax.plot(t, [q["ours"] for q in pts], color=SECURED_C, lw=2, label="FinSecure (non-linear, time ceiling)")
        ax.plot(t, [q["linear"] for q in pts], color=BASELINE_C, lw=2, label="Linear moving average")
        ax.set_ylim(0, 1)
        ax.set_xlabel("Minutes after the violation")
        ax.set_ylabel("Trust score")
        ax.set_title(f"Reputation laundering: {lau.get('cheap_actions')} cheap actions in {lau.get('minutes')} min",
                     loc="left", color=INK, fontsize=12)
        ax.legend(frameon=False, loc="lower right")
        fig.tight_layout()
        p = outdir / "trust_laundering.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        files.append(p.name)
    return files


def analyze(path: Path | str) -> dict:
    path = Path(path)
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not rows:
        print("no rows")
        return {}
    summary = summarize(rows)
    name = path.stem
    outdir = RESULTS_DIR / name
    outdir.mkdir(exist_ok=True)
    summary["charts"] = [f"{name}/{f}" for f in charts(summary, outdir)]
    (RESULTS_DIR / f"{name}_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (RESULTS_DIR / f"{name}.md").write_text(markdown(summary), encoding="utf-8")
    (RESULTS_DIR / "latest_summary.json").write_text(json.dumps({"file": name, **summary}, indent=2, default=str),
                                                     encoding="utf-8")
    print(markdown(summary))
    return summary


if __name__ == "__main__":
    analyze(sys.argv[1] if len(sys.argv) > 1 else RESULTS_DIR / "results_mock.jsonl")
