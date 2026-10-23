"""Small shared helpers: ids, canonical JSON, hashing, entity extraction, clock."""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def canonical(obj: Any) -> str:
    """Deterministic JSON used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------------- clock
class Clock:
    """Wall clock that scenarios can switch to simulated time (e.g. 'wait 10 minutes')."""

    def __init__(self) -> None:
        self._offset = 0.0
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return time.time() + self._offset

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._offset += seconds

    def reset(self) -> None:
        with self._lock:
            self._offset = 0.0

    def iso(self) -> str:
        return datetime.fromtimestamp(self.now(), tz=timezone.utc).isoformat(timespec="milliseconds")


CLOCK = Clock()

# ----------------------------------------------------------------------------- entities
ACC_RE = re.compile(r"\bACC-\d{4}\b", re.I)
CUST_RE = re.compile(r"\bCUST-\d{3}\b", re.I)
LOAN_RE = re.compile(r"\bLN-\d{3}\b", re.I)
CASE_RE = re.compile(r"\bFC-\d{3}\b", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"\+?\d[\d-]{9,}\d")
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr)\s*([\d,]+(?:\.\d+)?)|([\d,]+(?:\.\d+)?)\s*(?:rupees|/-)", re.I)


def _uniq(items) -> list[str]:
    seen, out = set(), []
    for i in items:
        u = i.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_entities(text: str) -> dict[str, list]:
    amounts = []
    for m in AMOUNT_RE.finditer(text or ""):
        raw = (m.group(1) or m.group(2) or "").replace(",", "")
        try:
            amounts.append(float(raw))
        except ValueError:
            pass
    return {
        "accounts": _uniq(ACC_RE.findall(text or "")),
        "customers": _uniq(CUST_RE.findall(text or "")),
        "loans": _uniq(LOAN_RE.findall(text or "")),
        "cases": _uniq(CASE_RE.findall(text or "")),
        "emails": [e for e in EMAIL_RE.findall(text or "")],
        "phones": PHONE_RE.findall(text or ""),
        "amounts": amounts,
    }


def inr(x: float) -> str:
    """Indian digit grouping: 150000 -> 1,50,000."""
    neg = x < 0
    x = abs(x)
    whole = int(round(x))
    s = str(whole)
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        parts = []
        while len(head) > 2:
            parts.insert(0, head[-2:])
            head = head[:-2]
        if head:
            parts.insert(0, head)
        s = ",".join(parts) + "," + tail
    return ("-" if neg else "") + "Rs " + s


OPERATIONS = [
    "account_inquiry", "transaction_history", "policy_query", "transfer", "freeze_account",
    "unfreeze_account", "loan_review", "loan_decision", "fraud_investigation", "customer_update",
    "customer_inquiry", "document_review"
]


def classify_operation(req: str) -> str:
    r = req.lower()
    ents = extract_entities(req)
    if "unfreeze" in r:
        return "unfreeze_account"
    if re.search(r"\b(transfer|send|pay|move)\b", r) and (ents["amounts"] or len(ents["accounts"]) >= 2):
        return "transfer"
    if ents["cases"]:
        return "fraud_investigation"
    if ents["loans"]:
        return "loan_decision" if re.search(r"\b(approve|reject|decide|decision)\b", r) else "loan_review"
    if "freeze" in r and ents["accounts"]:
        return "freeze_account"
    if re.search(r"\b(update|change)\b", r) and re.search(r"\b(email|phone|contact)\b", r):
        return "customer_update"
    if "document" in r or "kyc" in r:
        return "document_review"
    if re.search(r"\b(transactions?|statement|history|spent|spending)\b", r) and ents["accounts"]:
        return "transaction_history"
    if ents["customers"] and not ents["accounts"]:
        return "customer_inquiry"
    if ents["accounts"]:
        return "account_inquiry"
    return "policy_query"
