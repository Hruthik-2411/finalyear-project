"""Module 2b - Provenance DAG and delegation-chain verification.

Every envelope becomes a DAG node: node_hash = SHA-256(payload_hash || parent node hashes),
so a node's hash commits to its whole ancestry. Before a tool call is executed the gateway
walks the chain back to the root (the signed intent token) and checks that every hop exists,
was validly signed, belongs to the same intent, and has not been altered since it was stored.
"""
from __future__ import annotations

import json
import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.common import CLOCK, sha256
from backend.db.models import ProvenanceNode
from backend.gateway.envelope import Envelope
from backend.security.identity import CertificateAuthority


class ProvenanceStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, dict] = {}

    def reset(self) -> None:
        with self._lock:
            self._cache.clear()

    def node_hash(self, env: Envelope, s: Session) -> str:
        parents = [self.get(p, s) for p in env.parent_ids]
        return sha256(env.payload_hash + "".join(sorted(p["node_hash"] for p in parents if p)))

    def record(self, env: Envelope, sig_valid: bool, s: Session, verdict: str = "") -> dict:
        node = {"msg_id": env.msg_id, "run_id": env.run_id, "intent_id": env.intent_id,
                "parent_ids": list(env.parent_ids), "sender": env.sender, "receiver": env.receiver,
                "kind": env.kind, "envelope": env.to_dict(), "node_hash": self.node_hash(env, s),
                "sig_valid": sig_valid, "verdict": verdict, "ts": CLOCK.iso()}
        with self._lock:
            self._cache[env.msg_id] = node
        s.merge(ProvenanceNode(msg_id=env.msg_id, run_id=env.run_id, intent_id=env.intent_id,
                               parent_ids=json.dumps(env.parent_ids), sender=env.sender, receiver=env.receiver,
                               kind=env.kind, envelope=json.dumps(env.to_dict()), node_hash=node["node_hash"],
                               sig_valid=sig_valid, verdict=verdict, ts=node["ts"]))
        return node

    def set_verdict(self, msg_id: str, verdict: str, s: Session) -> None:
        with self._lock:
            if msg_id in self._cache:
                self._cache[msg_id]["verdict"] = verdict
        row = s.get(ProvenanceNode, msg_id)
        if row:
            row.verdict = verdict

    def get(self, msg_id: str, s: Session) -> dict | None:
        with self._lock:
            if msg_id in self._cache:
                return self._cache[msg_id]
        row = s.get(ProvenanceNode, msg_id)
        if row is None:
            return None
        node = {"msg_id": row.msg_id, "run_id": row.run_id, "intent_id": row.intent_id,
                "parent_ids": json.loads(row.parent_ids), "sender": row.sender, "receiver": row.receiver,
                "kind": row.kind, "envelope": json.loads(row.envelope), "node_hash": row.node_hash,
                "sig_valid": row.sig_valid, "verdict": row.verdict, "ts": row.ts}
        with self._lock:
            self._cache[msg_id] = node
        return node

    def verify_chain(self, env: Envelope, s: Session, max_depth: int = 64) -> tuple[bool, str, int]:
        """Walk from env's parents back to the intent root."""
        if not env.parent_ids:
            return False, "envelope has no parent: it is not part of any delegation chain", 0
        frontier, seen, depth, root_found = list(env.parent_ids), set(), 0, False
        while frontier:
            depth += 1
            if depth > max_depth:
                return False, "delegation chain too deep", depth
            mid = frontier.pop()
            if mid in seen:
                continue
            seen.add(mid)
            node = self.get(mid, s)
            if node is None:
                return False, f"parent {mid} does not exist (forged or missing hop)", depth
            if node["intent_id"] != env.intent_id:
                return False, f"hop {mid} belongs to a different intent", depth
            if not node["sig_valid"]:
                return False, f"hop {mid} from {node['sender']} was not validly signed", depth
            if node["verdict"] in {"BLOCK", "ISOLATE"}:
                return False, f"hop {mid} was blocked by the gateway; nothing may build on it", depth
            stored = Envelope.from_dict(node["envelope"])
            if not CertificateAuthority.verify_signature(
                    stored.cert_pem, stored.signing_bytes(), stored.signature):
                return False, f"hop {mid} was altered after it was recorded", depth
            if sha256(stored.payload_hash + "".join(sorted(
                    (self.get(p, s) or {}).get("node_hash", "") for p in stored.parent_ids))) != node["node_hash"]:
                return False, f"hash link broken at hop {mid}", depth
            if node["kind"] == "intent":
                if mid == env.intent_id:
                    root_found = True
                continue
            frontier.extend(node["parent_ids"])
        if not root_found:
            return False, "chain does not reach the signed intent token", depth
        return True, f"chain verified ({len(seen)} hops back to the intent)", depth

    def dag(self, run_id: str, s: Session) -> dict:
        rows = s.scalars(select(ProvenanceNode).where(ProvenanceNode.run_id == run_id)
                         .order_by(ProvenanceNode.ts)).all()
        nodes, edges = [], []
        for r in rows:
            env = json.loads(r.envelope)
            label = env["payload"].get("tool") or r.receiver
            nodes.append({"id": r.msg_id, "sender": r.sender, "receiver": r.receiver, "kind": r.kind,
                          "verdict": r.verdict, "label": label, "ts": r.ts, "hash": r.node_hash[:12]})
            for p in json.loads(r.parent_ids):
                edges.append({"from": p, "to": r.msg_id})
        return {"nodes": nodes, "edges": edges}
