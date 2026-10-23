"""FinSecure command line.

  python run.py setup                 create the database, seed data and agent certificates
  python run.py serve                 start the API + dashboard on http://127.0.0.1:8000
  python run.py ask "What is the balance of ACC-1012?"   run one request in the terminal
  python run.py scenario confused_deputy                  run one attack scenario
  python run.py eval [--quick|--full] [--ablation]        run the evaluation (see benchmark/runner.py)
  python run.py verify                verify the Merkle audit ledger
  python run.py tamper                edit one audit row directly in SQLite (for the demo)
  python run.py reset                 reset database, ledger and trust scores
  python run.py test                  run the automated tests (offline, mock LLM)
  python run.py check                 show configuration, LLM, OPA and LangGraph status

Options that work with every command:
  --provider groq|ollama|mock         override llm.provider from config.yaml
  --mode secured|baseline             override security.mode from config.yaml
"""
from __future__ import annotations

import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _pop_opt(argv: list[str], name: str) -> str | None:
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return None


def main() -> None:
    argv = sys.argv[1:]
    prov, mode = _pop_opt(argv, "--provider"), _pop_opt(argv, "--mode")
    if prov:
        os.environ["FINSECURE_PROVIDER"] = prov
    if mode:
        os.environ["FINSECURE_MODE"] = mode
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd, rest = argv[0], argv[1:]

    from backend.config import get_config

    cfg = get_config()

    if cmd == "setup":
        from backend.db.seed import reset_database
        from backend.security.identity import registry

        print("Seeding database:", reset_database())
        ids = registry()
        print("Certificates in data/pki for:", ", ".join(ids.identities))
        print("Done. Next: python run.py serve")
    elif cmd == "serve":
        import uvicorn

        from backend.db.seed import ensure_database

        ensure_database()
        host, port = cfg["server"]["host"], int(cfg["server"]["port"])
        print(f"FinSecure dashboard: http://{host}:{port}   (provider={cfg['llm']['provider']}, "
              f"mode={cfg['security']['mode']})")
        uvicorn.run("backend.app:app", host=host, port=port, log_level="warning")
    elif cmd == "ask":
        from backend.agents.workflow import run_request
        from backend.db.seed import ensure_database

        ensure_database()
        r = run_request(" ".join(rest) or "What is the current balance and status of account ACC-1012?")
        for t in r["trace"]:
            print(f"  {t['sender']:>12} -> {t['receiver']:<26} {t['verdict']:<9} {t['reason'][:90]}")
        print("\nFINAL ANSWER:\n" + r["final"])
    elif cmd == "scenario":
        from benchmark.scenarios import SCENARIOS, run_scenario

        name = rest[0] if rest else ""
        if name not in SCENARIOS:
            print("Scenarios:", ", ".join(SCENARIOS))
            return
        out = run_scenario(name)
        print(json.dumps({k: v for k, v in out.items() if k not in ("trace", "final")}, indent=2, default=str)[:4000])
    elif cmd == "eval":
        from benchmark.runner import main as eval_main

        eval_main(rest)
    elif cmd == "verify":
        from backend.db.database import session_scope
        from backend.gateway.gateway import gateway

        with session_scope() as s:
            print(json.dumps(gateway().ledger.verify(s), indent=2))
    elif cmd == "tamper":
        from sqlalchemy import select

        from backend.db.database import session_scope
        from backend.db.models import AuditEvent

        with session_scope() as s:
            row = s.scalars(select(AuditEvent).where(AuditEvent.event_type == "decision").order_by(AuditEvent.seq)).first()
            if not row:
                print("No audit events yet - run some requests first.")
                return
            d = json.loads(row.data)
            d["verdict"], d["reason"] = "APPROVE", "edited by insider"
            row.data = json.dumps(d, sort_keys=True, separators=(",", ":"))
            print(f"Edited audit event #{row.seq}. Now run: python run.py verify")
    elif cmd == "reset":
        from backend.db.seed import reset_database
        from backend.gateway.gateway import gateway

        print(reset_database())
        gateway().reset()
        print("Reset done.")
    elif cmd == "test":
        import subprocess

        try:
            import pytest  # noqa: F401

            sys.exit(subprocess.call([sys.executable, "-m", "pytest", "-q", "tests"] + rest))
        except ImportError:
            sys.exit(subprocess.call([sys.executable, "tests/run_all.py"]))
    elif cmd == "check":
        from backend.agents.graph_compat import LANGGRAPH_AVAILABLE
        from backend.config import groq_api_key
        from backend.security.policy import PolicyEngine

        print("LLM provider     :", cfg["llm"]["provider"], "| model:", cfg["llm"]["groq_model"])
        print("GROQ_API_KEY set :", bool(groq_api_key()))
        print("Security mode    :", cfg["security"]["mode"])
        print("OPA server       :", "reachable" if PolicyEngine().opa_status() else
              "NOT reachable (built-in policy evaluator will be used)")
        print("LangGraph        :", "installed" if LANGGRAPH_AVAILABLE else "not installed (compat runner used)")
        if cfg["llm"]["provider"] != "mock":
            try:
                from backend.llm.provider import get_llm

                out = get_llm().complete_json("check", "Return JSON {\"ok\": true}", "ping", {})
                print("LLM test call    :", out)
            except Exception as e:
                print("LLM test call    : FAILED -", e)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
