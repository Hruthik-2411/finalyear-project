"""Module 2a - Intent token (closes Gap 2 together with the provenance chain).

When a staff request arrives, its scope is fixed from the USER'S TEXT ONLY, before any
agent reads untrusted data: which operation, which entities, which write tools, what
maximum amount. The gateway signs this scope; it becomes the root of the delegation chain.
Every later tool call must fit inside it, so injected text can never widen what happens.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from backend.common import CLOCK, OPERATIONS, canonical, classify_operation, extract_entities, new_id
from backend.security.identity import CertificateAuthority
from backend.tools import banking_tools as bt
from backend.tools.registry import TOOLS

OP_WRITES: dict[str, list[str]] = {
    "account_inquiry": [], "transaction_history": [], "policy_query": [], "customer_inquiry": [],
    "document_review": [], "loan_review": [],
    "transfer": ["transfer_funds"],
    "freeze_account": ["freeze_account"],
    "unfreeze_account": ["unfreeze_account"],
    "loan_decision": ["update_loan_status"],
    "fraud_investigation": ["flag_fraud_case", "add_case_note", "freeze_account"],
    "customer_update": ["update_customer_contact"],
}
ALWAYS_ALLOWED = {"flag_for_review"}   # auditor may always raise a flag
ID_ARGS = {"account_id": "accounts", "src": "accounts", "dst": "accounts", "customer_id": "customers",
           "loan_id": "loans", "case_id": "cases"}


def build_scope(request: str, llm_operation: str | None) -> dict:
    op = llm_operation if llm_operation in OPERATIONS else classify_operation(request)
    ents = extract_entities(request)
    scope = {
        "operation": op,
        "allowed_writes": OP_WRITES.get(op, []),
        "entities": {k: ents[k] for k in ("accounts", "customers", "loans", "cases")},
        "emails": ents["emails"], "phones": ents["phones"],
        "max_amount": max(ents["amounts"]) if ents["amounts"] else None,
    }
    if op == "transfer" and len(ents["accounts"]) >= 2:
        scope["transfer"] = {"src": ents["accounts"][0], "dst": ents["accounts"][1]}
    if op == "loan_decision":
        r = request.lower()
        scope["loan_decision"] = "REJECTED" if re.search(r"\breject", r) else "APPROVED" if "approve" in r else None
    return scope


@dataclass
class IntentToken:
    id: str
    run_id: str
    request: str
    scope: dict
    created: str
    signature: str = ""
    cert_pem: str = ""

    def body(self) -> dict:
        return {"id": self.id, "run_id": self.run_id, "request": self.request, "scope": self.scope,
                "created": self.created}

    def to_dict(self) -> dict:
        return {**self.body(), "signature": self.signature}


def issue_token(run_id: str, request: str, scope: dict, gateway_identity) -> IntentToken:
    tok = IntentToken(id=new_id("intent-"), run_id=run_id, request=request, scope=scope, created=CLOCK.iso())
    tok.signature = gateway_identity.sign(canonical(tok.body()).encode())
    tok.cert_pem = gateway_identity.cert_pem
    return tok


def verify_token(tok: IntentToken) -> bool:
    return CertificateAuthority.verify_signature(tok.cert_pem, canonical(tok.body()).encode(), tok.signature)


def check_tool_scope(tok: IntentToken, tool: str, args: dict, s: Session) -> tuple[bool, str]:
    """Does this tool call fit the signed intent? Reads are always in scope (the burst
    limiter and OPA cover read abuse); writes must match operation, entities and amount."""
    spec = TOOLS.get(tool)
    if spec is None:
        return False, f"unknown tool {tool}"
    if spec.kind == "read" or tool in ALWAYS_ALLOWED:
        return True, "read-only call"
    scope = tok.scope
    if tool not in scope.get("allowed_writes", []):
        return False, (f"'{tool}' is not authorised by the user's request "
                       f"(operation '{scope.get('operation')}' allows {scope.get('allowed_writes') or 'no writes'})")
    related = bt.related_entities(s, scope.get("entities", {}))
    for arg, kind in ID_ARGS.items():
        if arg in args and args[arg]:
            val = str(args[arg]).upper()
            if val not in related.get(kind, set()):
                return False, f"{arg}={val} is outside the entities named in the request"
    if tool == "transfer_funds":
        t = scope.get("transfer") or {}
        if t and (str(args.get("src", "")).upper() != t["src"] or str(args.get("dst", "")).upper() != t["dst"]):
            return False, f"transfer route {args.get('src')} -> {args.get('dst')} differs from the request ({t['src']} -> {t['dst']})"
        mx = scope.get("max_amount")
        try:
            amt = bt.parse_amount(args.get("amount", 0))
        except bt.ToolError:
            return False, "invalid amount"
        if mx is None or amt > mx + 0.5:
            return False, f"amount {amt:.0f} exceeds the amount in the request ({mx})"
    if tool == "update_loan_status" and scope.get("loan_decision"):
        if str(args.get("status", "")).upper() != scope["loan_decision"]:
            return False, f"loan decision {args.get('status')} differs from the request ({scope['loan_decision']})"
    if tool == "update_customer_contact":
        if args.get("email") and args["email"] not in scope.get("emails", []):
            return False, "new email address does not come from the request"
        if args.get("phone") and args["phone"] not in scope.get("phones", []):
            return False, "new phone number does not come from the request"
    return True, "within intent scope"
