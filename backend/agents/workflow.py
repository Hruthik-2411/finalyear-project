"""The five FinSecure agents as a LangGraph workflow.

    orchestrator_intake -> planner -> researcher -> executor -> auditor -> orchestrator_final

Each agent signs its own envelopes with its X.509 identity and talks ONLY to the gateway:
messages go through gateway.send_message, tool calls through gateway.call_tool.
If a message is not delivered (blocked/isolated) the graph jumps straight to the final step.
"""
from __future__ import annotations

import json
import time
from typing import Any, TypedDict

from backend.agents.graph_compat import END, LANGGRAPH_AVAILABLE, START, StateGraph
from backend.common import CLOCK, new_id
from backend.config import get_config
from backend.db import database
from backend.db.models import RunRecord
from backend.events import BUS
from backend.gateway.envelope import Envelope
from backend.gateway.gateway import gateway
from backend.llm import prompts
from backend.llm.provider import LLMError, get_llm
from backend.security.identity import registry
from backend.tools.registry import untrusted_texts

MAX_RESEARCH_STEPS = 6
MAX_ACTIONS = 6


class FinState(TypedDict, total=False):
    run_id: str
    request: str
    intent: dict
    intent_id: str
    last_msg: str
    plan: list
    observations: list
    findings: str
    actions: list
    audit: dict
    final: str
    halted: str


def _spot() -> bool:
    cfg = get_config()["security"]
    return cfg["mode"] == "secured" and cfg.get("spotlighting", True)


def _send(sender: str, receiver: str, state: FinState, payload: dict, parents: list[str]) -> dict:
    env = Envelope(run_id=state["run_id"], intent_id=state["intent_id"], sender=sender, receiver=receiver,
                   kind="message", payload=payload, parent_ids=parents)
    env.sign(registry().get(sender))
    return gateway().send_message(env)


def _tool(sender: str, tool: str, args: dict, state: FinState, parents: list[str]) -> dict:
    env = Envelope(run_id=state["run_id"], intent_id=state["intent_id"], sender=sender, receiver=f"tool:{tool}",
                   kind="tool_call", payload={"tool": tool, "args": args}, parent_ids=parents)
    env.sign(registry().get(sender))
    return gateway().call_tool(env)


def _llm(purpose: str, sys_user: tuple[str, str], ctx: dict) -> dict:
    sys, user = sys_user
    return get_llm().complete_json(purpose, sys, user, ctx)


# ----------------------------------------------------------------------------- nodes
def orchestrator_intake(state: FinState) -> dict:
    req = state["request"]
    try:
        out = _llm("intent", prompts.intent_prompt(req), {"request": req})
    except LLMError as e:
        return {"halted": f"LLM error: {e}", "intent": {}, "intent_id": ""}
    tok = gateway().begin_run(state["run_id"], req, out.get("operation"))
    st = {**state, "intent_id": tok.id}
    res = _send("orchestrator", "planner", st, {"text": req, "scope": tok.scope}, [tok.id])
    upd = {"intent": {"operation": tok.scope["operation"], "scope": tok.scope}, "intent_id": tok.id,
           "last_msg": res["msg_id"], "observations": [], "actions": []}
    if not res["delivered"]:
        upd["halted"] = f"orchestrator message {res['verdict']}: {res['reason']}"
    return upd


def planner(state: FinState) -> dict:
    try:
        out = _llm("plan", prompts.plan_prompt(state["request"], state["intent"], _spot()),
                   {"request": state["request"], "intent": state["intent"]})
    except LLMError as e:
        return {"halted": f"LLM error: {e}"}
    steps = [s for s in out.get("steps", []) if isinstance(s, dict)][:6] or \
        [{"agent": "researcher", "goal": state["request"]}]
    res = _send("planner", "researcher", state, {"text": json.dumps(steps), "plan": steps}, [state["last_msg"]])
    upd = {"plan": steps, "last_msg": res["msg_id"]}
    if not res["delivered"]:
        upd["halted"] = f"planner message {res['verdict']}: {res['reason']}"
    return upd


def researcher(state: FinState) -> dict:
    obs: list[dict] = list(state.get("observations", []))
    ok_ids: list[str] = []
    for _ in range(MAX_RESEARCH_STEPS):
        ctx = {"request": state["request"], "intent": state["intent"], "plan": state.get("plan", []), "observations": obs}
        try:
            step = _llm("research_step", prompts.research_prompt(state["request"], state.get("plan", []), obs, _spot()), ctx)
        except LLMError as e:
            return {"halted": f"LLM error: {e}", "observations": obs}
        if step.get("action") != "call" or not step.get("tool"):
            break
        tool, args = str(step["tool"]), step.get("args") or {}
        if any(o["tool"] == tool and o["args"] == args for o in obs):
            break  # model is looping
        res = _tool("researcher", tool, args, state, [state["last_msg"]])
        obs.append({"tool": tool, "args": args, "status": res["status"],
                    "result": res["result"] if res["status"] == "ok" else res["reason"], "msg_id": res["msg_id"]})
        if res["status"] == "ok":
            ok_ids.append(res["msg_id"])
        if res["verdict"] == "ISOLATE":
            return {"observations": obs, "halted": "researcher isolated: " + res["reason"]}
    try:
        out = _llm("summarize", prompts.summarize_prompt(state["request"], obs, _spot()),
                   {"request": state["request"], "observations": obs})
        findings = str(out.get("findings", ""))
    except LLMError as e:
        return {"halted": f"LLM error: {e}", "observations": obs}
    untrusted = []
    for o in obs:
        if o["status"] == "ok":
            untrusted += untrusted_texts(o["tool"], o["result"])
    res = _send("researcher", "executor", state, {"text": findings, "untrusted": untrusted[:20]},
                [state["last_msg"]] + ok_ids)
    upd = {"observations": obs, "findings": res["payload"].get("text", findings) if res["delivered"] else findings,
           "last_msg": res["msg_id"]}
    if not res["delivered"]:
        upd["halted"] = f"researcher message {res['verdict']}: {res['reason']}"
    return upd


def executor(state: FinState) -> dict:
    ctx = {"request": state["request"], "intent": state["intent"], "plan": state.get("plan", []),
           "findings": state.get("findings", ""), "observations": state.get("observations", [])}
    try:
        out = _llm("execute", prompts.execute_prompt(state["request"], state.get("plan", []), state.get("findings", ""),
                                                     state.get("observations", []), _spot()), ctx)
    except LLMError as e:
        return {"halted": f"LLM error: {e}"}
    actions, ok_ids = [], []
    for call in (out.get("tool_calls") or [])[:MAX_ACTIONS]:
        if not isinstance(call, dict) or not call.get("tool"):
            continue
        res = _tool("executor", str(call["tool"]), call.get("args") or {}, state, [state["last_msg"]])
        actions.append({"tool": call["tool"], "args": call.get("args") or {}, "status": res["status"],
                        "verdict": res["verdict"], "reason": res["reason"], "approval_id": res.get("approval_id"),
                        "result": res["result"] if res["status"] == "ok" else None, "msg_id": res["msg_id"]})
        if res["status"] == "ok":
            ok_ids.append(res["msg_id"])
        if res["verdict"] == "ISOLATE":
            break
    summary = json.dumps([{k: a[k] for k in ("tool", "args", "status")} for a in actions]) or "[]"
    res = _send("executor", "auditor", state, {"text": summary, "actions": len(actions)}, [state["last_msg"]] + ok_ids)
    upd = {"actions": actions, "last_msg": res["msg_id"]}
    if not res["delivered"]:
        upd["halted"] = f"executor message {res['verdict']}: {res['reason']}"
    return upd


def auditor(state: FinState) -> dict:
    actions = [{k: a.get(k) for k in ("tool", "args", "status", "verdict")} for a in state.get("actions", [])]
    try:
        out = _llm("audit", prompts.audit_prompt(state["request"], actions, state.get("findings", "")),
                   {"request": state["request"], "actions": actions, "findings": state.get("findings", "")})
    except LLMError as e:
        out = {"verdict": "unknown", "note": f"audit unavailable: {e}"}
    audit = {"verdict": out.get("verdict", "ok"), "note": str(out.get("note", ""))[:400]}
    parents = [state["last_msg"]]
    if audit["verdict"] == "concern":
        r = _tool("auditor", "flag_for_review", {"note": audit["note"][:250]}, state, [state["last_msg"]])
        audit["flagged"] = r["status"]
        if r["status"] == "ok":
            parents.append(r["msg_id"])
    res = _send("auditor", "orchestrator", state, {"text": audit["note"], "verdict": audit["verdict"]}, parents)
    upd = {"audit": audit, "last_msg": res["msg_id"]}
    if not res["delivered"]:
        upd["halted"] = f"auditor message {res['verdict']}: {res['reason']}"
    return upd


def orchestrator_final(state: FinState) -> dict:
    if state.get("halted") and not state.get("observations"):
        return {"final": f"The request could not be completed: {state['halted']}"}
    ctx = {"request": state["request"], "findings": state.get("findings", ""), "actions": state.get("actions", []),
           "audit": state.get("audit", {}), "observations": state.get("observations", [])}
    try:
        out = _llm("final", prompts.final_prompt(state["request"], state.get("findings", ""), state.get("actions", []),
                                                 state.get("audit", {}), state.get("observations", [])), ctx)
        final = str(out.get("answer", ""))
    except LLMError as e:
        final = f"(final answer unavailable: {e})"
    if state.get("halted"):
        final += f"\n\nNote: the workflow was stopped early - {state['halted']}"
    return {"final": final}


def _route(next_node: str):
    def r(state: FinState) -> str:
        return "orchestrator_final" if state.get("halted") else next_node
    return r


def build_graph():
    g = StateGraph(FinState)
    for name, fn in [("orchestrator_intake", orchestrator_intake), ("planner", planner), ("researcher", researcher),
                     ("executor", executor), ("auditor", auditor), ("orchestrator_final", orchestrator_final)]:
        g.add_node(name, fn)
    g.add_edge(START, "orchestrator_intake")
    order = ["orchestrator_intake", "planner", "researcher", "executor", "auditor"]
    for a, b in zip(order, order[1:] + ["orchestrator_final"]):
        g.add_conditional_edges(a, _route(b), {b: b, "orchestrator_final": "orchestrator_final"})
    g.add_edge("orchestrator_final", END)
    return g.compile()


_GRAPH = None


def run_request(request: str) -> dict[str, Any]:
    """Run one staff request end to end and store it."""
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    gw = gateway()
    run_id = new_id("run-")
    cfg = get_config()
    t0 = time.perf_counter()
    started = CLOCK.iso()
    BUS.publish("run_started", {"run_id": run_id, "request": request, "mode": cfg["security"]["mode"]})
    try:
        state = _GRAPH.invoke({"run_id": run_id, "request": request}, config={"recursion_limit": 40})
        status = "halted" if state.get("halted") else "completed"
    except Exception as e:  # never crash the API on an agent error
        state = {"run_id": run_id, "request": request, "final": f"Error: {e}", "halted": str(e)}
        status = "error"
    gw.flush()
    gw.seal()
    ms = (time.perf_counter() - t0) * 1000
    trace = gw.traces.get(run_id, [])
    out = {"run_id": run_id, "request": request, "status": status, "mode": cfg["security"]["mode"],
           "provider": cfg["llm"]["provider"], "final": state.get("final", ""), "intent": state.get("intent", {}),
           "plan": state.get("plan", []), "observations": state.get("observations", []),
           "findings": state.get("findings", ""), "actions": state.get("actions", []), "audit": state.get("audit", {}),
           "halted": state.get("halted"), "trace": trace, "duration_ms": round(ms, 1),
           "langgraph": LANGGRAPH_AVAILABLE}
    with database.session_scope() as s:
        s.add(RunRecord(id=run_id, request=request, mode=out["mode"], provider=out["provider"], status=status,
                        final=out["final"], trace=json.dumps(out, default=str), started=started, duration_ms=ms))
    BUS.publish("run_finished", {"run_id": run_id, "status": status, "final": out["final"][:300],
                                 "duration_ms": round(ms, 1)})
    return out
