"""Module 4 - OPA policy engine (RBAC + ABAC, least privilege).

The gateway sends {role, action, tool, args, resource attributes, limits} to the OPA server
and gets back allow/deny with reasons and obligations (e.g. human_approval). If OPA is not
running, a Python evaluator with the SAME rules is used (tests check both agree), so the
system still works on a laptop without Docker. The result says which engine decided.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests
from sqlalchemy.orm import Session

from backend.config import get_config
from backend.db.models import Account, Loan
from backend.tools import banking_tools as bt
from backend.tools.registry import READ_TOOLS

EXECUTOR_TOOLS = {"flag_fraud_case", "add_case_note", "freeze_account", "transfer_funds", "update_loan_status",
                  "update_customer_contact", "unfreeze_account"}
ROLE_TOOLS = {"orchestrator": set(), "planner": set(), "researcher": set(READ_TOOLS),
              "executor": EXECUTOR_TOOLS, "auditor": set(READ_TOOLS) | {"flag_for_review"}}
ALLOWED_EDGES = {("orchestrator", "planner"), ("planner", "researcher"), ("researcher", "executor"),
                 ("executor", "auditor"), ("auditor", "orchestrator")}
PII_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+|\+?\d[\d-]{9,}\d")


@dataclass
class PolicyResult:
    allow: bool
    deny: list[str] = field(default_factory=list)
    obligations: list[str] = field(default_factory=list)
    severity: str = "medium"
    engine: str = "local"


def build_input(role: str, action: str, s: Session, tool: str | None = None, args: dict | None = None,
                receiver: str | None = None) -> dict:
    cfg = get_config()["banking"]
    args = dict(args or {})
    inp = {"action": action, "role": role, "tool": tool or "", "receiver": receiver or "", "args": args,
           "limits": {"single_txn_limit": cfg["single_txn_limit"], "daily_limit": cfg["daily_limit"]},
           "resource": {}}
    if tool == "transfer_funds":
        src, dst = s.get(Account, str(args.get("src", "")).upper()), s.get(Account, str(args.get("dst", "")).upper())
        try:
            args["amount"] = bt.parse_amount(args.get("amount", 0))
        except bt.ToolError:
            args["amount"] = 0.0
        args["src"], args["dst"] = str(args.get("src", "")), str(args.get("dst", ""))
        inp["resource"] = {"src_status": src.status if src else "MISSING", "dst_status": dst.status if dst else "MISSING",
                           "daily_outflow": bt.daily_outflow(s, args["src"]) if src else 0.0}
    elif tool == "update_loan_status":
        loan = s.get(Loan, str(args.get("loan_id", "")).upper())
        args["status"] = str(args.get("status", ""))
        inp["resource"] = {"credit_score": loan.credit_score if loan else 0,
                           "loan_status": loan.status if loan else "MISSING",
                           "loan_amount": loan.amount if loan else 0}
    return inp


def evaluate_local(inp: dict) -> PolicyResult:
    """Python twin of policies/finsecure.rego."""
    deny: list[str] = []
    obligations: list[str] = []
    tool, role, args, res, lim = inp.get("tool"), inp.get("role"), inp.get("args", {}), inp.get("resource", {}), inp.get("limits", {})
    if inp.get("action") == "tool_call" and tool not in ROLE_TOOLS.get(role, set()):
        deny.append(f"RBAC: role '{role}' may not use tool '{tool}'")
    if inp.get("action") == "message" and (role, inp.get("receiver")) not in ALLOWED_EDGES:
        deny.append(f"RBAC: '{role}' may not send messages to '{inp.get('receiver')}'")
    if tool == "transfer_funds":
        amt = float(args.get("amount", 0))
        if res.get("src_status") != "ACTIVE":
            deny.append("ABAC: source account is not ACTIVE (POL-002)")
        if res.get("dst_status") != "ACTIVE":
            deny.append("ABAC: destination account is not ACTIVE (POL-003)")
        if str(args.get("src", "")).upper() == str(args.get("dst", "")).upper():
            deny.append("ABAC: source and destination are the same account")
        if amt > lim["single_txn_limit"]:
            deny.append(f"ABAC: amount exceeds single-transaction limit of {lim['single_txn_limit']} (POL-001)")
        if res.get("daily_outflow", 0) + amt > lim["daily_limit"]:
            deny.append(f"ABAC: daily transfer limit of {lim['daily_limit']} would be exceeded (POL-001)")
    if tool == "update_loan_status" and str(args.get("status", "")).upper() == "APPROVED":
        if res.get("credit_score", 0) < 650:
            deny.append("ABAC: credit score below 650 cannot be approved (POL-008)")
        if res.get("loan_status") == "REJECTED":
            deny.append("ABAC: a REJECTED loan can only be reconsidered on a fresh application (POL-008)")
        if res.get("loan_amount", 0) > 1000000:
            obligations.append("human_approval")
    if tool in {"add_case_note", "flag_fraud_case", "flag_for_review"}:
        text = f"{args.get('note', '')} {args.get('reason', '')}"
        if PII_RE.search(text):
            deny.append("ABAC: personal data (email/phone) may not be written into case notes (POL-005)")
    if tool == "unfreeze_account":
        obligations.append("human_approval")
    severity = "high" if any(d.startswith("RBAC") for d in deny) else "medium"
    return PolicyResult(not deny, sorted(set(deny)), sorted(set(obligations)), severity, "local")


class PolicyEngine:
    def __init__(self) -> None:
        self._opa_ok: bool | None = None

    def opa_status(self) -> bool:
        cfg = get_config()["opa"]
        try:
            self._opa_ok = requests.get(cfg["url"] + "/health", timeout=cfg.get("timeout_s", 2)).ok
        except requests.RequestException:
            self._opa_ok = False
        return self._opa_ok

    def evaluate(self, inp: dict) -> PolicyResult:
        cfg = get_config()["opa"]
        if self._opa_ok is None:
            self.opa_status()
        if self._opa_ok:
            try:
                r = requests.post(cfg["url"] + cfg["decision_path"], json={"input": inp}, timeout=cfg.get("timeout_s", 2))
                r.raise_for_status()
                d = r.json().get("result")
                if d is not None:
                    return PolicyResult(bool(d.get("allow")), list(d.get("deny", [])), list(d.get("obligations", [])),
                                        d.get("severity", "medium"), "opa")
            except requests.RequestException:
                self._opa_ok = False
        if not cfg.get("fallback_local", True):
            return PolicyResult(False, ["OPA unavailable and local fallback disabled"], [], "high", "none")
        return evaluate_local(inp)
