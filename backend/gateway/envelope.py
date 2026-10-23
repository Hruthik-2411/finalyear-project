"""The envelope: every inter-agent message and every tool call travels in one of these."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from backend.common import CLOCK, canonical, new_id, sha256


@dataclass
class Envelope:
    run_id: str
    intent_id: str
    sender: str
    receiver: str                     # agent name, or "tool:<name>"
    kind: str                         # intent | message | tool_call | tool_result
    payload: dict[str, Any]
    parent_ids: list[str] = field(default_factory=list)
    msg_id: str = field(default_factory=lambda: new_id("m-"))
    timestamp: str = field(default_factory=CLOCK.iso)
    cert_pem: str = ""
    signature: str = ""

    def body(self) -> dict:
        d = asdict(self)
        d.pop("signature")
        d.pop("cert_pem")
        return d

    def signing_bytes(self) -> bytes:
        return canonical(self.body()).encode("utf-8")

    @property
    def payload_hash(self) -> str:
        return sha256(canonical(self.payload))

    def sign(self, identity) -> "Envelope":
        self.cert_pem = identity.cert_pem
        self.signature = identity.sign(self.signing_bytes())
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Envelope":
        return cls(**d)

    @property
    def tool(self) -> str | None:
        return self.receiver[5:] if self.receiver.startswith("tool:") else None
