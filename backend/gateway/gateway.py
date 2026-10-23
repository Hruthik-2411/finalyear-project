"""The Zero-Trust Gateway - the single choke point (complete mediation).

Agents never hold a DB session, never call tools and never talk to each other directly.
Every inter-agent message and every tool call is a signed Envelope handed to this class,
which runs the checks in a fixed order, asks the decision engine, then delivers/executes,
escalates to a human, restricts, blocks or isolates. Everything is written to the
provenance DAG and the Merkle audit ledger, and streamed to the dashboard.

mode = "baseline": Phase-1 behaviour - log only, approve everything.
mode = "secured" : full pipeline; individual modules can be switched off (ablation).
"""
from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any

from sqlalchemy import select

from backend.common import CLOCK, new_id
from backend.config import get_config
from backend.db import database
from backend.db.models import ApprovalRequest, IntentToken as IntentRow, Revocation
from backend.events import BUS
from backend.gateway.envelope import Envelope
from backend.llm.provider import get_llm
from backend.security import intent as intent_mod
from backend.security.audit import AuditLedger
from backend.security.behaviour import AnomalyDetector, BurstLimiter, TrustEngine
from backend.security.decision import Check, Decision, decide
from backend.security.identity import CertificateAuthority, registry
from backend.security.policy import PolicyEngine, build_input
from backend.security.provenance import ProvenanceStore
from backend.security.shield import REDACTED, PromptShield, spotlight
from backend.tools.banking_tools import ToolError
from backend.tools.registry import TOOLS, map_untrusted, untrusted_texts

AGENT_NAMES = {"orchestrator", "planner", "researcher", "executor", "auditor"}


class Gateway:
    def __init__(self) -> None:
        self.ids = registry()
        self.prov = ProvenanceStore()
        self.shield = PromptShield(None)
        self.policy = PolicyEngine()
        self.burst = BurstLimiter()
        self.trust = TrustEngine()
        self.anomaly = AnomalyDetector()
        self.ledger = AuditLedger()
        self.tokens: dict[str, intent_mod.IntentToken] = {}
        self.tainted: set[str] = set()
        self.revoked: set[str] = set()
        self.traces: dict[str, list[dict]] = {}
        self.lock = threading.RLock()
        self._q: queue.Queue = queue.Queue()
        self._worker = threading.Thread(target=self._async_loop, daemon=True)
        self._worker.start()

    # ------------------------------------------------------------------ configuration
    @property
    def mode(self) -> str:
        return get_config()["security"]["mode"]

    def module_on(self, name: str) -> bool:
        return self.mode == "secured" and bool(get_config()["security"]["modules"].get(name, True))

    def refresh_llm(self) -> None:
        try:
            self.shield = PromptShield(get_llm(refresh=True))
        except Exception:
            self.shield = PromptShield(None)

    def reset(self) -> None:
        """Forget all runtime state (used together with a DB reset)."""
        self.flush()
        with self.lock:
            self.prov.reset()
            self.shield.reset_cache()
            self.burst.reset()
            self.trust.reset()
            self.anomaly.reset()
            self.ledger.reset()
            self.tokens.clear()
            self.tainted.clear()
            self.revoked.clear()
            self.traces.clear()
            CLOCK.reset()
        self.refresh_llm()

    # ------------------------------------------------------------------ async track
    def _async_loop(self) -> None:
        while True:
            fn, args = self._q.get()
            try:
                fn(*args)
            except Exception as e:  # pragma: no cover
                BUS.publish("error", {"where": "async", "error": str(e)})
            finally:
                self._q.task_done()

    def flush(self) -> None:
        """Wait for the asynchronous track (trust rewards, anomaly analysis) to finish."""
        self._q.join()

    def _async_good(self, agent: str, weight_key: str, amount: float) -> None:
        if self.module_on("trust"):
            t = self.trust.reward(agent, weight_key)
            BUS.publish("trust", {"agent": agent, "score": round(t, 4), "event": f"good:{weight_key}"})
            note = self.anomaly.observe(agent, amount)
            if note:
                t = self.trust.penalize(agent, "low", "anomaly: " + note)
                BUS.publish("trust", {"agent": agent, "score": round(t, 4), "event": "anomaly: " + note})

    # ------------------------------------------------------------------ intent root
    def begin_run(self, run_id: str, request: str, llm_operation: str | None) -> intent_mod.IntentToken:
        scope = intent_mod.build_scope(request, llm_operation)
        gw = self.ids.get("gateway")
        tok = intent_mod.issue_token(run_id, request, scope, gw)
        env = Envelope(run_id=run_id, intent_id=tok.id, sender="gateway", receiver="orchestrator", kind="intent",
                       payload={"scope": scope, "token_signature": tok.signature[:32]}, parent_ids=[], msg_id=tok.id)
        env.sign(gw)
        with self.lock, database.session_scope() as s:
            self.tokens[tok.id] = tok
            s.add(IntentRow(id=tok.id, run_id=run_id, request=request, scope=json.dumps(scope),
                            signature=tok.signature, created=tok.created))
            self.prov.record(env, True, s, "ISSUED")
            self.ledger.append(s, "intent_issued", "gateway", {"intent_id": tok.id, "run_id": run_id, "scope": scope})
        self.traces.setdefault(run_id, []).append({"msg_id": tok.id, "sender": "gateway", "receiver": "orchestrator",
                                                   "kind": "intent", "verdict": "ISSUED", "rule": 0,
                                                   "reason": f"scope: {scope['operation']}, writes={scope['allowed_writes']}",
                                                   "checks": [], "ts": CLOCK.iso(), "ms": 0})
        BUS.publish("intent", {"run_id": run_id, "intent_id": tok.id, "scope": scope})
        return tok

    # ------------------------------------------------------------------ checks
    def _identity(self, env: Envelope) -> tuple[Check, str, bool]:
        """Returns (check, role, signature_valid)."""
        ca = self.ids.ca
        cc = ca.check_certificate(env.cert_pem, self.revoked) if env.cert_pem else None
        sig_ok = bool(env.cert_pem) and CertificateAuthority.verify_signature(env.cert_pem, env.signing_bytes(), env.signature)
        if cc is None:
            return Check("identity", False, "no certificate presented", "identity"), env.sender, False
        if not cc.ok:
            return Check("identity", False, cc.reason, "identity", {"serial": cc.serial}), env.sender, sig_ok
        if cc.name != env.sender:
            return Check("identity", False, f"certificate belongs to '{cc.name}', not claimed sender '{env.sender}'",
                         "identity"), cc.role, sig_ok
        if not sig_ok:
            return Check("identity", False, "signature invalid (message forged or altered)", "identity"), cc.role, False
        return Check("identity", True, f"X.509 valid, signature valid, role={cc.role}", "identity",
                     {"serial": cc.serial}), cc.role, True

    def _shield_text(self, texts: list[str]) -> tuple[float, str, str]:
        best = (0.0, "low", "")
        for t in texts:
            if not t:
                continue
            r = self.shield.scan(t)
            if r.score > best[0]:
                best = (r.score, r.level, f"{r.source}: {r.detail}")
        return best

    def _process(self, env: Envelope, s) -> tuple[Decision, dict]:
        """Run the synchronous checks and the decision engine. Returns (decision, extras)."""
        extras: dict[str, Any] = {"obligations": [], "role": env.sender}
        tool = env.tool
        spec = TOOLS.get(tool) if tool else None
        tier = spec.tier if spec else 0
        checks: list[Check] = []
        id_check, role, sig_ok = self._identity(env)
        extras["sig_ok"] = sig_ok
        if self.mode == "baseline":
            extras["role"] = env.sender
            return Decision("APPROVE", 0, "baseline: logging only", []), extras
        if self.module_on("identity"):
            checks.append(id_check)
            extras["role"] = role if id_check.passed else env.sender
        tok = self.tokens.get(env.intent_id)
        if self.module_on("intent"):
            ok, why, _ = self.prov.verify_chain(env, s)
            if ok and (tok is None or not intent_mod.verify_token(tok)):
                ok, why = False, "intent token missing or its signature is invalid"
            checks.append(Check("chain", ok, why, "high"))
            if env.kind == "tool_call" and tok is not None:
                ok2, why2 = intent_mod.check_tool_scope(tok, tool, env.payload.get("args", {}), s)
                checks.append(Check("intent", ok2, why2, "high"))
        if self.module_on("policy"):
            if env.kind == "tool_call":
                inp = build_input(extras["role"], "tool_call", s, tool=tool, args=env.payload.get("args", {}))
            else:
                inp = build_input(extras["role"], "message", s, receiver=env.receiver)
            pr = self.policy.evaluate(inp)
            extras["obligations"] = pr.obligations
            sev = "high" if pr.severity == "high" else "low"
            checks.append(Check("policy", pr.allow, "; ".join(pr.deny) or f"allowed by {pr.engine.upper()}",
                                sev, {"engine": pr.engine, "obligations": pr.obligations}))
        if self.module_on("shield"):
            if env.kind == "tool_call":
                args = env.payload.get("args", {})
                texts = [str(v) for k, v in args.items() if k in ("memo", "note", "reason", "email")]
                score, level, src = self._shield_text(texts)
                checks.append(Check("shield", level != "high", f"args risk {score:.2f} ({level}) {src}".strip(), "medium",
                                    {"score": score, "level": level}))
            elif env.sender in ("orchestrator", "planner"):
                # these agents have only seen the signed, trusted staff request - nothing to scan
                checks.append(Check("shield", True, "trusted context (request + plan only)", "low", {"score": 0.0}))
            else:
                texts = [str(env.payload.get("text", ""))] + [str(x) for x in env.payload.get("untrusted", [])]
                score, level, src = self._shield_text(texts)
                if level == "high":
                    self.tainted.add(env.intent_id)
                # messages are sanitised (high-risk lines redacted), not dropped, so the workflow continues
                checks.append(Check("shield", True, f"message risk {score:.2f} ({level})"
                                    + ("; injection redacted, chain marked tainted" if level == "high" else ""), "low",
                                    {"score": score, "level": level}))
        if self.module_on("burst") and env.kind == "tool_call" and spec:
            try:
                amt = float(str(env.payload.get("args", {}).get("amount", 0) or 0).replace(",", "")) \
                    if tool == "transfer_funds" else 0.0
            except ValueError:
                amt = 0.0
            ok, why = self.burst.check(env.sender, spec.kind, amt)
            checks.append(Check("burst", ok, why, "low"))
        trust = self.trust.score(env.sender)
        recent = self.trust.recent_blocks(env.sender)
        if self.module_on("trust"):
            th = get_config()["trust"]["thresholds"]
            checks.append(Check("trust", trust >= th["normal"], f"trust {trust:.2f}" +
                                (f", ceiling {self.trust.ceiling(env.sender):.2f}" if trust < 1 else ""), "low",
                                {"score": trust}))
        d = decide(checks, tier=tier, kind=env.kind, trust=trust, recent_blocks=recent,
                   tainted=env.intent_id in self.tainted, obligations=extras["obligations"])
        return d, extras

    def _after_decision(self, env: Envelope, d: Decision, extras: dict, s) -> None:
        """Penalties, isolation, audit, provenance, event stream."""
        if self.mode == "secured" and env.sender in AGENT_NAMES:
            failed = [c for c in d.checks if not c.passed and c.name not in ("trust",)]
            if d.verdict in ("BLOCK", "ISOLATE", "RESTRICT") and self.module_on("trust"):
                idc = next((c for c in d.checks if c.name == "identity"), None)
                if idc is not None and not idc.passed:
                    BUS.publish("alert", {"type": "impersonation", "claimed": env.sender, "detail": idc.detail})
                elif failed:
                    sev = failed[0].severity if failed[0].severity in ("low", "medium", "high") else "medium"
                    t = self.trust.penalize(env.sender, sev, failed[0].detail)
                    n = self.trust.record_block(env.sender)
                    BUS.publish("trust", {"agent": env.sender, "score": round(t, 4), "event": f"violation: {failed[0].detail}"[:160],
                                          "recent_blocks": n})
                    th = get_config()["trust"]
                    if d.verdict != "ISOLATE" and (t < th["thresholds"]["blocked"] or n >= th["isolate_blocks"]):
                        d.verdict, d.rule, d.reason = "ISOLATE", 5, d.reason + f" -> trust {t:.2f}, {n} blocks: agent isolated"
            if d.verdict == "ISOLATE":
                self.isolate(env.sender, d.reason, s)
        self.prov.record(env, extras.get("sig_ok", False), s, d.verdict)
        self.ledger.append(s, "decision", env.sender, {
            "msg_id": env.msg_id, "run_id": env.run_id, "kind": env.kind, "receiver": env.receiver,
            "payload_hash": env.payload_hash, "verdict": d.verdict, "rule": d.rule, "reason": d.reason,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in d.checks]})

    def _trace(self, env: Envelope, d: Decision, ms: float, extra: dict | None = None) -> dict:
        args = env.payload.get("args", {}) if env.kind == "tool_call" else {}
        item = {"msg_id": env.msg_id, "run_id": env.run_id, "sender": env.sender, "receiver": env.receiver,
                "kind": env.kind, "tool": env.tool, "args": args, "verdict": d.verdict, "rule": d.rule,
                "reason": d.reason, "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in d.checks],
                "ts": CLOCK.iso(), "ms": round(ms, 2), "mode": self.mode}
        if extra:
            item.update(extra)
        self.traces.setdefault(env.run_id, []).append(item)
        BUS.publish("envelope", item)
        return item

    # ------------------------------------------------------------------ public API
    def send_message(self, env: Envelope) -> dict:
        t0 = time.perf_counter()
        with self.lock, database.session_scope() as s:
            d, extras = self._process(env, s)
            self._after_decision(env, d, extras, s)
            delivered = d.verdict in ("APPROVE", "RESTRICT", "ESCALATE")
            payload = env.payload
            if self.module_on("shield") and delivered:
                payload = self._sanitize_message(payload)
        if delivered and self.mode == "secured":
            self._q.put((self._async_good, (env.sender, "message", 0.0)))
        self._trace(env, d, (time.perf_counter() - t0) * 1000)
        return {"delivered": delivered, "verdict": d.verdict, "reason": d.reason, "payload": payload,
                "msg_id": env.msg_id}

    def _sanitize_message(self, payload: dict) -> dict:
        p = dict(payload)
        if isinstance(p.get("text"), str):
            lines = []
            for line in p["text"].split("\n"):
                lines.append(REDACTED if self.shield.scan(line).level == "high" else line)
            p["text"] = "\n".join(lines)
        return p

    def call_tool(self, env: Envelope) -> dict:
        t0 = time.perf_counter()
        tool = env.tool
        spec = TOOLS.get(tool)
        args = env.payload.get("args", {}) or {}
        result: Any = None
        status = "blocked"
        approval_id = None
        with self.lock, database.session_scope() as s:
            d, extras = self._process(env, s)
            self._after_decision(env, d, extras, s)
            if spec is None:
                status, result = "error", f"unknown tool {tool}"
            elif d.verdict == "APPROVE":
                try:
                    with s.begin_nested():
                        result = spec.fn(s, **args)
                    status = "ok"
                except ToolError as e:
                    status, result = "error", str(e)
                except TypeError as e:
                    status, result = "error", f"bad arguments: {e}"
                except Exception as e:  # never let a tool bug crash the run
                    status, result = "error", f"{type(e).__name__}: {e}"
            elif d.verdict == "ESCALATE":
                approval_id = new_id("apr-")
                s.add(ApprovalRequest(id=approval_id, run_id=env.run_id, agent=env.sender, tool=tool,
                                      args=json.dumps(args), reason=d.reason, envelope=json.dumps(env.to_dict()),
                                      created=CLOCK.iso()))
                status, result = "pending_approval", {"approval_id": approval_id, "reason": d.reason}
                BUS.publish("approval", {"id": approval_id, "tool": tool, "args": args, "reason": d.reason})
            else:
                status, result = d.verdict.lower(), d.reason
            # sanitise untrusted fields of successful read results before the agent sees them
            if status == "ok" and spec and spec.kind == "read" and self.mode == "secured":
                result = self._sanitize_result(env, tool, result, s)
            if status == "ok":
                self.ledger.append(s, "tool_executed", env.sender, {"msg_id": env.msg_id, "tool": tool, "args": args})
        if status == "ok" and self.mode == "secured" and spec:
            wk = "read" if spec.kind == "read" else f"tier{spec.tier}"
            try:
                amt = float(str(args.get("amount", 0) or 0).replace(",", "")) if tool == "transfer_funds" else 0.0
            except ValueError:
                amt = 0.0
            self._q.put((self._async_good, (env.sender, wk, amt)))
        self._trace(env, d, (time.perf_counter() - t0) * 1000, {"status": status, "approval_id": approval_id})
        return {"status": status, "verdict": d.verdict, "reason": d.reason, "result": result, "msg_id": env.msg_id,
                "approval_id": approval_id}

    def _sanitize_result(self, env: Envelope, tool: str, result: Any, s) -> Any:
        flagged: list[dict] = []
        shield_on = self.module_on("shield")
        spot = get_config()["security"].get("spotlighting", True)

        def fix(text: str) -> str:
            if shield_on:
                r = self.shield.scan(text)
                if r.level == "high":
                    flagged.append({"score": r.score, "level": r.level, "source": r.source, "excerpt": text[:160]})
                    self.tainted.add(env.intent_id)
                    return spotlight(REDACTED) if spot else REDACTED
                if r.level == "medium":
                    flagged.append({"score": r.score, "level": r.level, "source": r.source, "excerpt": text[:160]})
                    self.tainted.add(env.intent_id)
            return spotlight(text) if spot else text

        if not untrusted_texts(tool, result):
            return result
        out = map_untrusted(tool, result, fix)
        if flagged:
            self.ledger.append(s, "shield_flag", "gateway", {"msg_id": env.msg_id, "tool": tool, "flags": flagged})
            BUS.publish("alert", {"type": "prompt_injection", "tool": tool, "run_id": env.run_id, "flags": flagged})
            self.traces.setdefault(env.run_id, []).append({
                "msg_id": env.msg_id + "-shield", "run_id": env.run_id, "sender": "gateway", "receiver": env.sender,
                "kind": "tool_result", "tool": tool, "args": {}, "verdict": "SANITIZED", "rule": 4,
                "reason": f"Prompt Shield flagged {len(flagged)} untrusted field(s): "
                          + ", ".join(f"{f['level']} {f['score']:.2f}" for f in flagged),
                "checks": [], "ts": CLOCK.iso(), "ms": 0, "mode": self.mode})
        return out

    # ------------------------------------------------------------------ isolation & approvals
    def isolate(self, agent: str, reason: str, s) -> None:
        ident = self.ids.identities.get(agent)
        if not ident or ident.serial in self.revoked:
            return
        self.revoked.add(ident.serial)
        s.merge(Revocation(serial=ident.serial, agent=agent, reason=reason[:500], ts=CLOCK.iso()))
        self.trust.set_score(agent, 0.0, "isolated: " + reason[:120])
        self.ledger.append(s, "agent_isolated", "gateway", {"agent": agent, "serial": ident.serial, "reason": reason})
        BUS.publish("alert", {"type": "isolation", "agent": agent, "reason": reason})

    def reinstate(self, agent: str) -> dict:
        """Admin action: issue a fresh certificate and reset trust to the initial value."""
        with self.lock, database.session_scope() as s:
            ident = self.ids.ca.issue(agent, self.ids.identities[agent].role)
            self.ids.identities[agent] = ident
            self.trust.set_score(agent, get_config()["trust"]["initial"], "reinstated by admin")
            self.ledger.append(s, "agent_reinstated", "admin", {"agent": agent, "serial": ident.serial})
        BUS.publish("trust", {"agent": agent, "score": get_config()["trust"]["initial"], "event": "reinstated"})
        return {"agent": agent, "serial": ident.serial}

    def decide_approval(self, approval_id: str, approve: bool, approver: str = "staff") -> dict:
        with self.lock, database.session_scope() as s:
            a = s.get(ApprovalRequest, approval_id)
            if a is None or a.status != "PENDING":
                return {"ok": False, "error": "approval not found or already decided"}
            args = json.loads(a.args)
            result: Any = None
            if approve:
                spec = TOOLS[a.tool]
                pr = self.policy.evaluate(build_input(a.agent, "tool_call", s, tool=a.tool, args=args))
                if not pr.allow:
                    a.status, a.result = "REJECTED", "policy denies: " + "; ".join(pr.deny)
                    result = a.result
                else:
                    try:
                        with s.begin_nested():
                            result = spec.fn(s, **args)
                        a.status, a.result = "APPROVED", json.dumps(result)
                    except ToolError as e:
                        a.status, a.result = "REJECTED", f"tool error: {e}"
                        result = a.result
            else:
                a.status, a.result = "REJECTED", "rejected by " + approver
            a.decided = CLOCK.iso()
            self.ledger.append(s, "human_decision", approver, {"approval_id": approval_id, "tool": a.tool, "args": args,
                                                                "status": a.status})
            out = {"ok": True, "id": approval_id, "status": a.status, "result": result}
        BUS.publish("approval", {"id": approval_id, "status": out["status"]})
        return out

    def pending_approvals(self) -> list[dict]:
        with database.session_scope() as s:
            rows = s.scalars(select(ApprovalRequest).order_by(ApprovalRequest.created.desc())).all()
            return [{"id": r.id, "run_id": r.run_id, "agent": r.agent, "tool": r.tool, "args": json.loads(r.args),
                     "reason": r.reason, "status": r.status, "created": r.created, "decided": r.decided,
                     "result": r.result} for r in rows]

    def seal(self) -> dict | None:
        if self.mode != "secured":
            return None
        with self.lock, database.session_scope() as s:
            return self.ledger.seal(s)


_GATEWAY: Gateway | None = None
_GW_LOCK = threading.Lock()


def gateway() -> Gateway:
    global _GATEWAY
    with _GW_LOCK:
        if _GATEWAY is None:
            _GATEWAY = Gateway()
            _GATEWAY.refresh_llm()
        return _GATEWAY
