"""The 15 banking tools. Pure functions over the DB - no LLM, no security logic.

Security is NOT enforced here on purpose: the core banking functions only check that
records exist and balances suffice. All authorisation lives in the Zero-Trust gateway,
so the baseline (gateway in logging mode) shows what a compromised agent could do.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import (
    Account, CaseNote, Customer, CustomerDocument, FraudCase, Loan, Policy, Transaction,
)


class ToolError(Exception):
    pass


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def parse_amount(x) -> float:
    """LLMs sometimes send '25,000' or 'Rs 25000' instead of a number."""
    if isinstance(x, (int, float)):
        return float(x)
    cleaned = re.sub(r"(?i)rs\.?|inr|₹|,|\s", "", str(x))
    try:
        return float(cleaned)
    except ValueError:
        raise ToolError(f"invalid amount {x!r}")


def _acc(s: Session, account_id: str) -> Account:
    acc = s.get(Account, str(account_id).upper())
    if not acc:
        raise ToolError(f"account {account_id} not found")
    return acc


# ----------------------------------------------------------------------------- read tools
def get_customer(s: Session, customer_id: str) -> dict:
    c = s.get(Customer, str(customer_id).upper())
    if not c:
        raise ToolError(f"customer {customer_id} not found")
    accounts = [a.id for a in s.scalars(select(Account).where(Account.customer_id == c.id))]
    return {"customer_id": c.id, "name": c.name, "email": c.email, "phone": c.phone, "city": c.city,
            "kyc_status": c.kyc_status, "risk_profile": c.risk_profile, "segment": c.segment, "accounts": accounts}


def get_account(s: Session, account_id: str) -> dict:
    a = _acc(s, account_id)
    return {"account_id": a.id, "customer_id": a.customer_id, "type": a.type, "balance": round(a.balance, 2),
            "status": a.status, "opened": a.opened}


def get_transactions(s: Session, account_id: str, limit: int = 5) -> dict:
    a = _acc(s, account_id)
    rows = s.scalars(select(Transaction).where(Transaction.account_id == a.id)
                     .order_by(Transaction.timestamp.desc()).limit(max(1, min(int(limit or 5), 20)))).all()
    return {"account_id": a.id, "transactions": [
        {"txn_id": t.id, "date": t.timestamp[:10], "counterparty": t.counterparty, "amount": t.amount,
         "direction": t.direction, "channel": t.channel, "memo": t.memo} for t in rows]}


_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "of", "for", "to", "and", "or", "in", "on", "our", "is", "are", "what", "be", "by",
         "with", "summarise", "summarize", "policy", "policies", "please", "about", "me", "tell", "rs"}


def _tokens(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOP]


def search_policy(s: Session, query: str, top_k: int = 2) -> dict:
    """TF-IDF similarity search over the policy knowledge base (pure Python)."""
    pols = s.scalars(select(Policy)).all()
    docs = [_tokens(p.title + " " + p.title + " " + p.content) for p in pols]
    n = len(docs)
    df = Counter(w for d in docs for w in set(d))
    idf = {w: math.log((1 + n) / (1 + c)) + 1 for w, c in df.items()}

    def vec(toks: list[str]) -> dict[str, float]:
        tf = Counter(toks)
        v = {w: (tf[w] / len(toks)) * idf.get(w, 1.0) for w in tf} if toks else {}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {w: x / norm for w, x in v.items()}

    q = vec(_tokens(query))
    scored = []
    for p, d in zip(pols, docs):
        dv = vec(d)
        scored.append((sum(q.get(w, 0) * dv.get(w, 0) for w in q), p))
    scored.sort(key=lambda x: (-x[0], x[1].id))
    k = max(1, min(int(top_k or 2), 4))
    return {"query": query, "results": [
        {"policy_id": p.id, "title": p.title, "category": p.category, "score": round(sc, 3), "content": p.content}
        for sc, p in scored[:k] if sc > 0]}


def get_loan(s: Session, loan_id: str) -> dict:
    l = s.get(Loan, str(loan_id).upper())
    if not l:
        raise ToolError(f"loan {loan_id} not found")
    return {"loan_id": l.id, "customer_id": l.customer_id, "amount": l.amount, "purpose": l.purpose,
            "credit_score": l.credit_score, "status": l.status, "application_text": l.application_text}


def get_fraud_case(s: Session, case_id: str) -> dict:
    c = s.get(FraudCase, str(case_id).upper())
    if not c:
        raise ToolError(f"fraud case {case_id} not found")
    notes = [n.text for n in s.scalars(select(CaseNote).where(CaseNote.case_id == c.id))]
    return {"case_id": c.id, "account_id": c.account_id, "severity": c.severity, "status": c.status,
            "description": c.description, "reporter_notes": c.reporter_notes, "case_notes": notes}


def read_customer_document(s: Session, customer_id: str) -> dict:
    cid = str(customer_id).upper()
    docs = s.scalars(select(CustomerDocument).where(CustomerDocument.customer_id == cid)).all()
    if not docs:
        raise ToolError(f"no documents for {customer_id}")
    return {"customer_id": cid, "documents": [{"doc_id": d.id, "title": d.title, "content": d.content} for d in docs]}


def list_fraud_cases(s: Session, status: str = "OPEN") -> dict:
    rows = s.scalars(select(FraudCase).where(FraudCase.status == str(status).upper()).limit(10)).all()
    return {"status": status, "cases": [{"case_id": c.id, "account_id": c.account_id, "severity": c.severity}
                                        for c in rows]}


# ----------------------------------------------------------------------------- write tools
def flag_fraud_case(s: Session, case_id: str, reason: str = "") -> dict:
    c = s.get(FraudCase, str(case_id).upper())
    if not c:
        raise ToolError(f"fraud case {case_id} not found")
    c.status = "ESCALATED"
    s.add(CaseNote(case_id=c.id, author="system", text=f"Escalated: {reason}"[:500], created=_now()))
    return {"case_id": c.id, "status": c.status}


def add_case_note(s: Session, case_id: str, note: str) -> dict:
    c = s.get(FraudCase, str(case_id).upper())
    if not c:
        raise ToolError(f"fraud case {case_id} not found")
    s.add(CaseNote(case_id=c.id, author="agent", text=str(note)[:1000], created=_now()))
    return {"case_id": c.id, "note_added": True}


def freeze_account(s: Session, account_id: str, reason: str = "") -> dict:
    a = _acc(s, account_id)
    a.status = "FROZEN"
    return {"account_id": a.id, "status": a.status}


def unfreeze_account(s: Session, account_id: str, reason: str = "") -> dict:
    a = _acc(s, account_id)
    a.status = "ACTIVE"
    return {"account_id": a.id, "status": a.status}


def transfer_funds(s: Session, src: str, dst: str, amount: float, memo: str = "") -> dict:
    a, b = _acc(s, src), _acc(s, dst)
    amount = parse_amount(amount)
    if amount <= 0:
        raise ToolError("amount must be positive")
    if a.id == b.id:
        raise ToolError("source and destination are the same")
    if a.balance < amount:
        raise ToolError(f"insufficient balance in {a.id}")
    a.balance -= amount
    b.balance += amount
    ts = _now()
    count = len(s.scalars(select(Transaction.id)).all())
    s.add(Transaction(id=f"TXN-{count + 1:05d}", account_id=a.id, counterparty=b.id, amount=amount,
                      direction="DEBIT", channel="FINSECURE", memo=str(memo)[:200] or "transfer", timestamp=ts))
    s.add(Transaction(id=f"TXN-{count + 2:05d}", account_id=b.id, counterparty=a.id, amount=amount,
                      direction="CREDIT", channel="FINSECURE", memo=str(memo)[:200] or "transfer", timestamp=ts))
    return {"src": a.id, "dst": b.id, "amount": amount, "src_balance": round(a.balance, 2), "status": "COMPLETED"}


def update_loan_status(s: Session, loan_id: str, status: str, reason: str = "") -> dict:
    l = s.get(Loan, str(loan_id).upper())
    if not l:
        raise ToolError(f"loan {loan_id} not found")
    status = str(status).upper()
    if status not in {"APPROVED", "REJECTED", "PENDING"}:
        raise ToolError("status must be APPROVED, REJECTED or PENDING")
    l.status = status
    return {"loan_id": l.id, "status": l.status}


def update_customer_contact(s: Session, customer_id: str, email: str | None = None, phone: str | None = None) -> dict:
    c = s.get(Customer, str(customer_id).upper())
    if not c:
        raise ToolError(f"customer {customer_id} not found")
    if email:
        c.email = str(email)
    if phone:
        c.phone = str(phone)
    return {"customer_id": c.id, "email": c.email, "phone": c.phone}


def flag_for_review(s: Session, note: str, run_ref: str = "") -> dict:
    return {"flagged": True, "note": str(note)[:300]}


# ----------------------------------------------------------------------------- helpers for policy input
def daily_outflow(s: Session, account_id: str) -> float:
    today = datetime.now().strftime("%Y-%m-%d")
    rows = s.scalars(select(Transaction).where(Transaction.account_id == str(account_id).upper(),
                                               Transaction.direction == "DEBIT",
                                               Transaction.channel == "FINSECURE")).all()
    return float(sum(t.amount for t in rows if t.timestamp.startswith(today)))


def related_entities(s: Session, ids: dict[str, list[str]]) -> dict[str, set[str]]:
    """Expand intent entities through TRUSTED structured links (never through free text)."""
    acc, cust, case, loan = (set(map(str.upper, ids.get(k, []))) for k in ("accounts", "customers", "cases", "loans"))
    for cid in list(case):
        c = s.get(FraudCase, cid)
        if c:
            acc.add(c.account_id)
    for lid in list(loan):
        l = s.get(Loan, lid)
        if l:
            cust.add(l.customer_id)
    for aid in list(acc):
        a = s.get(Account, aid)
        if a:
            cust.add(a.customer_id)
    for cid in list(cust):
        for a in s.scalars(select(Account).where(Account.customer_id == cid)):
            acc.add(a.id)
    return {"accounts": acc, "customers": cust, "cases": case, "loans": loan}


def account_snapshot(s: Session, account_id: str) -> dict[str, Any] | None:
    a = s.get(Account, str(account_id).upper())
    return None if a is None else {"id": a.id, "status": a.status, "balance": a.balance}
