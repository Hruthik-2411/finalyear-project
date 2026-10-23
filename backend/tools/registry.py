"""Tool registry: name -> function, tier, arguments, and which result fields are untrusted text."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from backend.tools import banking_tools as bt


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable
    kind: str                 # read | write
    tier: int                 # 0 = read, 1 = reversible write, 2 = irreversible / high impact
    description: str
    params: dict[str, str]
    untrusted_fields: tuple[str, ...] = field(default_factory=tuple)


TOOLS: dict[str, ToolSpec] = {t.name: t for t in [
    ToolSpec("get_customer", bt.get_customer, "read", 0, "Customer profile and their account ids",
             {"customer_id": "CUST-xxx"}),
    ToolSpec("get_account", bt.get_account, "read", 0, "Account balance, status and owner",
             {"account_id": "ACC-xxxx"}),
    ToolSpec("get_transactions", bt.get_transactions, "read", 0, "Recent transactions of an account",
             {"account_id": "ACC-xxxx", "limit": "int, default 5"}, ("memo",)),
    ToolSpec("search_policy", bt.search_policy, "read", 0, "Search the bank policy knowledge base",
             {"query": "text"}, ("content",)),
    ToolSpec("get_loan", bt.get_loan, "read", 0, "Loan application details", {"loan_id": "LN-xxx"},
             ("application_text",)),
    ToolSpec("get_fraud_case", bt.get_fraud_case, "read", 0, "Fraud case details and notes",
             {"case_id": "FC-xxx"}, ("reporter_notes", "case_notes")),
    ToolSpec("read_customer_document", bt.read_customer_document, "read", 0, "Documents uploaded by the customer",
             {"customer_id": "CUST-xxx"}, ("content",)),
    ToolSpec("list_fraud_cases", bt.list_fraud_cases, "read", 0, "List fraud cases by status",
             {"status": "OPEN | INVESTIGATING | ESCALATED | CLOSED"}),
    ToolSpec("flag_fraud_case", bt.flag_fraud_case, "write", 1, "Escalate a fraud case",
             {"case_id": "FC-xxx", "reason": "text"}),
    ToolSpec("add_case_note", bt.add_case_note, "write", 1, "Add a note to a fraud case",
             {"case_id": "FC-xxx", "note": "text"}),
    ToolSpec("freeze_account", bt.freeze_account, "write", 1, "Freeze an account (reversible)",
             {"account_id": "ACC-xxxx", "reason": "text"}),
    ToolSpec("flag_for_review", bt.flag_for_review, "write", 1, "Auditor: flag the run for human review",
             {"note": "text"}),
    ToolSpec("transfer_funds", bt.transfer_funds, "write", 2, "Move money between accounts",
             {"src": "ACC-xxxx", "dst": "ACC-xxxx", "amount": "number (rupees)", "memo": "text"}),
    ToolSpec("update_loan_status", bt.update_loan_status, "write", 2, "Approve or reject a loan",
             {"loan_id": "LN-xxx", "status": "APPROVED | REJECTED | PENDING", "reason": "text"}),
    ToolSpec("update_customer_contact", bt.update_customer_contact, "write", 2, "Change customer email/phone",
             {"customer_id": "CUST-xxx", "email": "text (optional)", "phone": "text (optional)"}),
    ToolSpec("unfreeze_account", bt.unfreeze_account, "write", 2, "Unfreeze an account",
             {"account_id": "ACC-xxxx", "reason": "text"}),
]}

READ_TOOLS = [n for n, t in TOOLS.items() if t.kind == "read"]
WRITE_TOOLS = [n for n, t in TOOLS.items() if t.kind == "write" and n != "flag_for_review"]


def describe(names: list[str]) -> str:
    lines = []
    for n in names:
        t = TOOLS[n]
        args = ", ".join(f"{k}: {v}" for k, v in t.params.items())
        lines.append(f"- {n}({args}): {t.description}")
    return "\n".join(lines)


def untrusted_texts(tool: str, result) -> list[str]:
    """Collect free-text values from a tool result that came from outside the bank's control."""
    spec = TOOLS.get(tool)
    if not spec or not spec.untrusted_fields:
        return []
    out: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in spec.untrusted_fields:
                    if isinstance(v, list):
                        out.extend(str(i) for i in v)
                    elif v:
                        out.append(str(v))
                else:
                    walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(result)
    return out


def map_untrusted(tool: str, result, fn):
    """Return a copy of result with every untrusted string replaced by fn(text)."""
    spec = TOOLS.get(tool)
    if not spec or not spec.untrusted_fields:
        return result

    def walk(x):
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                if k in spec.untrusted_fields:
                    out[k] = [fn(str(i)) for i in v] if isinstance(v, list) else (fn(str(v)) if v else v)
                else:
                    out[k] = walk(v)
            return out
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x

    return walk(result)
