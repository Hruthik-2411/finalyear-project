"""FastAPI application: REST API + WebSocket event stream + the built dashboard."""
from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select

from backend.agents.graph_compat import LANGGRAPH_AVAILABLE
from backend.config import RESULTS_DIR, ROOT, get_config, groq_api_key
from backend.db.database import session_scope
from backend.db.models import (
    Account, AuditEvent, CaseNote, Customer, FraudCase, Loan, Policy, RunRecord, Transaction,
)
from backend.db.seed import ensure_database, reset_database
from backend.events import BUS
from backend.gateway.gateway import gateway
from backend.llm.provider import STATS, LLMError, get_llm

app = FastAPI(title="FinSecure Zero-Trust MAS", version="1.0")
ensure_database()
GW = gateway()


class RunBody(BaseModel):
    request: str


class SettingsBody(BaseModel):
    mode: str | None = None
    provider: str | None = None
    modules: dict[str, bool] | None = None


class ApprovalBody(BaseModel):
    approve: bool
    approver: str = "staff"


# ----------------------------------------------------------------------------- status & settings
@app.get("/api/status")
def status():
    cfg = get_config()
    return {"mode": cfg["security"]["mode"], "provider": cfg["llm"]["provider"], "model": cfg["llm"]["groq_model"],
            "modules": cfg["security"]["modules"], "spotlighting": cfg["security"].get("spotlighting", True),
            "opa": GW.policy.opa_status(), "langgraph": LANGGRAPH_AVAILABLE, "groq_key": bool(groq_api_key()),
            "llm_stats": STATS.snapshot()}


@app.post("/api/settings")
def settings(body: SettingsBody):
    cfg = get_config()
    if body.mode:
        if body.mode not in ("baseline", "secured"):
            raise HTTPException(400, "mode must be baseline or secured")
        cfg["security"]["mode"] = body.mode
    if body.modules:
        for k, v in body.modules.items():
            if k in cfg["security"]["modules"]:
                cfg["security"]["modules"][k] = bool(v)
    if body.provider:
        old = cfg["llm"]["provider"]
        cfg["llm"]["provider"] = body.provider
        try:
            get_llm(refresh=True)
        except LLMError as e:
            cfg["llm"]["provider"] = old
            get_llm(refresh=True)
            raise HTTPException(400, str(e))
    GW.refresh_llm()
    BUS.publish("settings", {"mode": cfg["security"]["mode"], "provider": cfg["llm"]["provider"]})
    return status()


@app.post("/api/reset")
def reset():
    counts = reset_database()
    GW.reset()
    BUS.clear()
    BUS.publish("reset", counts)
    return {"ok": True, "seeded": counts}


# ----------------------------------------------------------------------------- operations
@app.post("/api/run")
def run(body: RunBody):
    from backend.agents.workflow import run_request

    if not body.request.strip():
        raise HTTPException(400, "empty request")
    return run_request(body.request.strip())


@app.get("/api/runs")
def runs(limit: int = 30):
    with session_scope() as s:
        rows = s.scalars(select(RunRecord).order_by(RunRecord.created_at.desc()).limit(limit)).all()
        return [{"id": r.id, "request": r.request, "mode": r.mode, "provider": r.provider, "status": r.status,
                 "final": r.final[:300], "started": r.started, "duration_ms": round(r.duration_ms, 1)} for r in rows]


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    with session_scope() as s:
        r = s.get(RunRecord, run_id)
        if r is None:
            raise HTTPException(404, "run not found")
        return json.loads(r.trace)


@app.get("/api/dag/{run_id}")
def dag(run_id: str):
    with session_scope() as s:
        return GW.prov.dag(run_id, s)


# ----------------------------------------------------------------------------- security views
@app.get("/api/trust")
def trust():
    return {"current": GW.trust.snapshot(), "history": GW.trust.history[-2000:],
            "thresholds": get_config()["trust"]["thresholds"]}


@app.post("/api/agents/{agent}/reinstate")
def reinstate(agent: str):
    if agent not in GW.ids.identities:
        raise HTTPException(404, "unknown agent")
    return GW.reinstate(agent)


@app.get("/api/approvals")
def approvals():
    return GW.pending_approvals()


@app.post("/api/approvals/{approval_id}")
def decide(approval_id: str, body: ApprovalBody):
    return GW.decide_approval(approval_id, body.approve, body.approver)


@app.get("/api/audit")
def audit(limit: int = 200, offset: int = 0):
    with session_scope() as s:
        total = s.scalar(select(func.count()).select_from(AuditEvent)) or 0
        rows = s.scalars(select(AuditEvent).order_by(AuditEvent.seq.desc()).offset(offset).limit(limit)).all()
        return {"total": total, "last_sealed": GW.ledger.last_sealed(), "roots": GW.ledger._roots()[-20:],
                "events": [{"seq": r.seq, "ts": r.ts, "type": r.event_type, "actor": r.actor,
                            "data": json.loads(r.data), "leaf": r.leaf_hash} for r in rows]}


@app.post("/api/audit/seal")
def audit_seal():
    return {"sealed": GW.seal()}


@app.post("/api/audit/verify")
def audit_verify():
    with session_scope() as s:
        return GW.ledger.verify(s)


@app.post("/api/audit/tamper")
def audit_tamper():
    """Demo only: edit the first sealed decision event directly in the database."""
    with session_scope() as s:
        row = s.scalars(select(AuditEvent).where(AuditEvent.event_type == "decision",
                                                 AuditEvent.seq <= max(GW.ledger.last_sealed(), 1))
                        .order_by(AuditEvent.seq)).first()
        if row is None:
            raise HTTPException(400, "no sealed decision events yet - run a request first")
        d = json.loads(row.data)
        d["verdict"], d["reason"] = "APPROVE", "edited by insider"
        row.data = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return {"edited_seq": row.seq}


@app.get("/api/audit/proof/{seq}")
def audit_proof(seq: int):
    with session_scope() as s:
        p = GW.ledger.proof(s, seq)
    if p is None:
        raise HTTPException(404, "event not sealed yet")
    return p


@app.get("/api/report", response_class=HTMLResponse)
def report():
    from backend.security.report import build_report

    return build_report(GW)


@app.get("/api/events")
def events(since: int = 0):
    return BUS.since(since)


@app.websocket("/ws")
async def ws(socket: WebSocket):
    await socket.accept()
    last = 0
    try:
        while True:
            new = BUS.since(last)
            if new:
                last = new[-1]["id"]
                await socket.send_text(json.dumps(new, default=str))
            await asyncio.sleep(0.3)
    except (WebSocketDisconnect, RuntimeError):
        return


# ----------------------------------------------------------------------------- attack lab
@app.get("/api/scenarios")
def scenarios():
    from benchmark.scenarios import SCENARIOS

    return [{"id": k, "title": v[0], "description": v[1]} for k, v in SCENARIOS.items()]


@app.post("/api/scenarios/{name}")
def run_scenario(name: str):
    from benchmark.scenarios import SCENARIOS, run_scenario as rs

    if name not in SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    out = rs(name)
    return JSONResponse(json.loads(json.dumps(out, default=str)))


# ----------------------------------------------------------------------------- results
@app.get("/api/results")
def results():
    p = RESULTS_DIR / "latest_summary.json"
    if not p.exists():
        return {"available": False}
    return {"available": True, **json.loads(p.read_text(encoding="utf-8"))}


# ----------------------------------------------------------------------------- bank data
TABLES = {"customers": Customer, "accounts": Account, "transactions": Transaction, "loans": Loan,
          "fraud_cases": FraudCase, "policies": Policy, "case_notes": CaseNote}


@app.get("/api/data/{table}")
def data(table: str, q: str = "", limit: int = 200):
    model = TABLES.get(table)
    if model is None:
        raise HTTPException(404, "unknown table")
    with session_scope() as s:
        stmt = select(model)
        if table == "transactions":
            stmt = stmt.order_by(Transaction.timestamp.desc())
        rows = s.scalars(stmt.limit(2000)).all()
        out = [{c.name: getattr(r, c.name) for c in model.__table__.columns} for r in rows]
    if q:
        ql = q.lower()
        out = [r for r in out if ql in json.dumps(r, default=str).lower()]
    return out[:limit]


@app.get("/api/overview")
def overview():
    with session_scope() as s:
        acc = s.scalars(select(Account)).all()
        cases = s.scalars(select(FraudCase)).all()
        decisions = [json.loads(e.data)["verdict"] for e in
                     s.scalars(select(AuditEvent).where(AuditEvent.event_type == "decision")).all()]
        nruns = s.scalar(select(func.count()).select_from(RunRecord)) or 0
    return {"accounts": len(acc), "total_balance": round(sum(a.balance for a in acc if a.id != "ACC-9999"), 2),
            "frozen": sum(1 for a in acc if a.status == "FROZEN"),
            "attacker_balance": next((a.balance for a in acc if a.id == "ACC-9999"), 0),
            "open_cases": sum(1 for c in cases if c.status in ("OPEN", "INVESTIGATING", "ESCALATED")),
            "pending_approvals": sum(1 for a in GW.pending_approvals() if a["status"] == "PENDING"),
            "runs": nruns, "decisions": dict(Counter(decisions)), "trust": GW.trust.snapshot()}


# ----------------------------------------------------------------------------- static files
if RESULTS_DIR.exists():
    app.mount("/results", StaticFiles(directory=str(RESULTS_DIR)), name="results")

DIST = ROOT / "frontend" / "dist"


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    target = DIST / path
    if path and target.is_file():
        return FileResponse(target)
    index = DIST / "index.html"
    if index.exists():
        return FileResponse(index)
    return HTMLResponse("<h2>FinSecure API is running.</h2><p>The dashboard has not been built "
                        "(frontend/dist missing). API docs: <a href='/docs'>/docs</a></p>")
