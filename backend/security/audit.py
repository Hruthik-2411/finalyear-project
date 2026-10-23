"""Module 8 - Merkle-tree audit ledger (tamper-evident).

* Every event is a row in `audit_events`; leaf = SHA-256(canonical JSON of the event).
* Every `batch_size` events (and at the end of each run) the pending leaves are sealed:
  a Merkle root is computed, signed with the ledger's RSA key, and appended to
  data/ledger_roots.jsonl - a separate append-only file OUTSIDE the database, so an
  attacker who edits the DB cannot simply recompute the root.
* verify() recomputes every leaf from the stored data, rebuilds each root and compares
  it with the signed root, pinpointing modified, deleted or inserted rows.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.common import CLOCK, canonical, sha256
from backend.config import abs_path, get_config
from backend.db.models import AuditEvent
from backend.security.identity import CertificateAuthority, registry


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256("")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Inclusion proof: list of (sibling_hash, 'L'|'R')."""
    proof, level, i = [], list(leaves), index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        proof.append((level[sib], "L" if sib < i else "R"))
        level = [sha256(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
        i //= 2
    return proof


def verify_proof(leaf: str, proof: list[tuple[str, str]], root: str) -> bool:
    h = leaf
    for sib, side in proof:
        h = sha256(sib + h) if side == "L" else sha256(h + sib)
    return h == root


def event_leaf(seq: int, ts: str, event_type: str, actor: str, data: str) -> str:
    return sha256(canonical({"seq": seq, "ts": ts, "type": event_type, "actor": actor, "data": data}))


class AuditLedger:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.roots_path: Path = abs_path(get_config()["audit"]["roots_file"])
        self.roots_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ write side
    def reset(self) -> None:
        with self.lock:
            self.roots_path.write_text("", encoding="utf-8")

    def append(self, s: Session, event_type: str, actor: str, data: dict) -> int:
        with self.lock:
            seq = (s.scalar(select(func.max(AuditEvent.seq))) or 0) + 1
            ts = CLOCK.iso()
            payload = canonical(data)
            s.add(AuditEvent(seq=seq, ts=ts, event_type=event_type, actor=actor, data=payload,
                             leaf_hash=event_leaf(seq, ts, event_type, actor, payload)))
            s.flush()
            # Baseline (Phase 1) keeps a plain log only; Merkle sealing is part of the secured layer.
            if get_config()["security"]["mode"] == "secured" and \
                    seq - self.last_sealed() >= get_config()["audit"]["batch_size"]:
                self.seal(s)
            return seq

    def _roots(self) -> list[dict]:
        if not self.roots_path.exists():
            return []
        return [json.loads(l) for l in self.roots_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def last_sealed(self) -> int:
        roots = self._roots()
        return roots[-1]["to_seq"] if roots else 0

    def seal(self, s: Session) -> dict | None:
        with self.lock:
            start = self.last_sealed() + 1
            rows = s.scalars(select(AuditEvent).where(AuditEvent.seq >= start).order_by(AuditEvent.seq)).all()
            if not rows:
                return None
            leaves = [r.leaf_hash for r in rows]
            root = merkle_root(leaves)
            ident = registry().get("ledger")
            body = {"batch": len(self._roots()) + 1, "from_seq": rows[0].seq, "to_seq": rows[-1].seq,
                    "root": root, "leaves": leaves, "sealed_at": CLOCK.iso()}
            body["signature"] = ident.sign(canonical({k: body[k] for k in ("batch", "from_seq", "to_seq", "root", "leaves")}).encode())
            with open(self.roots_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(body) + "\n")
            return {k: body[k] for k in ("batch", "from_seq", "to_seq", "root")}

    # ------------------------------------------------------------------ verify side
    def verify(self, s: Session) -> dict:
        ident = registry().get("ledger")
        rows = {r.seq: r for r in s.scalars(select(AuditEvent).order_by(AuditEvent.seq))}
        report = {"ok": True, "batches": 0, "events_checked": 0, "problems": [], "unsealed": 0}
        for b in self._roots():
            report["batches"] += 1
            sig_ok = CertificateAuthority.verify_signature(
                ident.cert_pem, canonical({k: b[k] for k in ("batch", "from_seq", "to_seq", "root", "leaves")}).encode(),
                b["signature"])
            if not sig_ok:
                report["problems"].append({"batch": b["batch"], "seq": None, "problem": "root signature invalid (roots file edited)"})
            if merkle_root(b["leaves"]) != b["root"]:
                report["problems"].append({"batch": b["batch"], "seq": None, "problem": "sealed leaves do not match root"})
            recomputed = []
            for i, seq in enumerate(range(b["from_seq"], b["to_seq"] + 1)):
                r = rows.get(seq)
                if r is None:
                    report["problems"].append({"batch": b["batch"], "seq": seq, "problem": "event deleted"})
                    recomputed.append(None)
                    continue
                leaf = event_leaf(r.seq, r.ts, r.event_type, r.actor, r.data)
                recomputed.append(leaf)
                report["events_checked"] += 1
                if leaf != b["leaves"][i]:
                    report["problems"].append({"batch": b["batch"], "seq": seq,
                                               "problem": "event content modified",
                                               "event_type": r.event_type, "actor": r.actor})
            if None not in recomputed and merkle_root(recomputed) != b["root"]:
                if not any(p["batch"] == b["batch"] for p in report["problems"]):
                    report["problems"].append({"batch": b["batch"], "seq": None, "problem": "root mismatch"})
        last = self.last_sealed()
        report["unsealed"] = sum(1 for k in rows if k > last)
        report["ok"] = not report["problems"]
        return report

    def proof(self, s: Session, seq: int) -> dict | None:
        for b in self._roots():
            if b["from_seq"] <= seq <= b["to_seq"]:
                idx = seq - b["from_seq"]
                p = merkle_proof(b["leaves"], idx)
                r = s.get(AuditEvent, seq)
                leaf = event_leaf(r.seq, r.ts, r.event_type, r.actor, r.data) if r else None
                return {"seq": seq, "batch": b["batch"], "root": b["root"], "leaf": leaf,
                        "proof": p, "valid": bool(leaf) and verify_proof(leaf, p, b["root"])}
        return None
