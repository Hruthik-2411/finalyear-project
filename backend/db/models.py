"""SQLAlchemy models for the FinSecure banking environment and the security layer."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Float, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- banking data
class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # CUST-001
    name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(120))
    phone: Mapped[str] = mapped_column(String(20))
    city: Mapped[str] = mapped_column(String(40))
    kyc_status: Mapped[str] = mapped_column(String(16))                  # VERIFIED / PENDING
    risk_profile: Mapped[str] = mapped_column(String(16))                # LOW / MEDIUM / HIGH
    segment: Mapped[str] = mapped_column(String(16))                     # RETAIL / PREMIUM


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # ACC-1001
    customer_id: Mapped[str] = mapped_column(String(16), index=True)
    type: Mapped[str] = mapped_column(String(16))                        # SAVINGS / CURRENT
    balance: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16))                      # ACTIVE / FROZEN / SUSPENDED
    opened: Mapped[str] = mapped_column(String(10))


class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # TXN-00001
    account_id: Mapped[str] = mapped_column(String(16), index=True)
    counterparty: Mapped[str] = mapped_column(String(40))
    amount: Mapped[float] = mapped_column(Float)
    direction: Mapped[str] = mapped_column(String(6))                    # DEBIT / CREDIT
    channel: Mapped[str] = mapped_column(String(10))                     # UPI / NEFT / IMPS ...
    memo: Mapped[str] = mapped_column(Text)                              # untrusted free text
    timestamp: Mapped[str] = mapped_column(String(25))


class Loan(Base):
    __tablename__ = "loans"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # LN-001
    customer_id: Mapped[str] = mapped_column(String(16), index=True)
    amount: Mapped[float] = mapped_column(Float)
    purpose: Mapped[str] = mapped_column(String(40))
    credit_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))                      # PENDING / APPROVED / REJECTED
    application_text: Mapped[str] = mapped_column(Text)                  # untrusted free text


class FraudCase(Base):
    __tablename__ = "fraud_cases"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # FC-001
    account_id: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(10))                    # LOW / MEDIUM / HIGH
    status: Mapped[str] = mapped_column(String(16))                      # OPEN / INVESTIGATING / ESCALATED / CLOSED
    description: Mapped[str] = mapped_column(Text)
    reporter_notes: Mapped[str] = mapped_column(Text)                    # untrusted (external reporter)


class CaseNote(Base):
    __tablename__ = "case_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(16), index=True)
    author: Mapped[str] = mapped_column(String(20))
    text: Mapped[str] = mapped_column(Text)
    created: Mapped[str] = mapped_column(String(25))


class CustomerDocument(Base):
    __tablename__ = "customer_documents"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # DOC-001
    customer_id: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(80))
    content: Mapped[str] = mapped_column(Text)                           # untrusted (uploaded)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)        # POL-001
    title: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(20))
    content: Mapped[str] = mapped_column(Text)


# --------------------------------------------------------------------------- security layer
class AuditEvent(Base):
    __tablename__ = "audit_events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(32))
    data: Mapped[str] = mapped_column(Text)                              # canonical JSON
    leaf_hash: Mapped[str] = mapped_column(String(64))


class ProvenanceNode(Base):
    __tablename__ = "provenance"
    msg_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    intent_id: Mapped[str] = mapped_column(String(40), index=True)
    parent_ids: Mapped[str] = mapped_column(Text)                        # JSON list
    sender: Mapped[str] = mapped_column(String(40))
    receiver: Mapped[str] = mapped_column(String(60))
    kind: Mapped[str] = mapped_column(String(16))
    envelope: Mapped[str] = mapped_column(Text)                          # canonical JSON (with signature)
    node_hash: Mapped[str] = mapped_column(String(64))                   # H(payload_hash || parent node hashes)
    sig_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    verdict: Mapped[str] = mapped_column(String(16), default="")
    ts: Mapped[str] = mapped_column(String(32))


class IntentToken(Base):
    __tablename__ = "intent_tokens"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    request: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)                             # JSON
    signature: Mapped[str] = mapped_column(Text)
    created: Mapped[str] = mapped_column(String(32))


class Revocation(Base):
    __tablename__ = "revocations"
    serial: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    ts: Mapped[str] = mapped_column(String(32))


class ApprovalRequest(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(40))
    agent: Mapped[str] = mapped_column(String(32))
    tool: Mapped[str] = mapped_column(String(40))
    args: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    envelope: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="PENDING")   # PENDING / APPROVED / REJECTED
    created: Mapped[str] = mapped_column(String(32))
    decided: Mapped[str] = mapped_column(String(32), default="")
    result: Mapped[str] = mapped_column(Text, default="")


class RunRecord(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    request: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(12))
    provider: Mapped[str] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(16))
    final: Mapped[str] = mapped_column(Text, default="")
    trace: Mapped[str] = mapped_column(Text, default="[]")               # JSON list of gateway decisions
    started: Mapped[str] = mapped_column(String(32))
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
