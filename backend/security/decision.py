"""Module 7 - Decision engine: readable rules, checked top to bottom, first match wins."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from backend.config import get_config


@dataclass
class Check:
    name: str          # identity | intent | chain | shield | policy | burst | trust
    passed: bool
    detail: str
    severity: str = "medium"
    data: dict = field(default_factory=dict)


@dataclass
class Decision:
    verdict: str       # APPROVE | RESTRICT | ESCALATE | BLOCK | ISOLATE
    rule: int
    reason: str
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "rule": self.rule, "reason": self.reason,
                "checks": [asdict(c) for c in self.checks]}


RULES = [
    (1, "Identity fails or certificate revoked", "BLOCK"),
    (2, "Delegation chain broken or call outside the intent scope", "BLOCK"),
    (3, "OPA policy denies", "BLOCK"),
    (4, "Prompt Shield: high-risk injection in the message", "BLOCK"),
    (5, "Trust below 0.2, or repeated blocks", "ISOLATE"),
    (6, "Burst limiter tripped", "RESTRICT"),
    (7, "Tier-2 (irreversible) action while trust < 0.4", "BLOCK"),
    (8, "Tier-2 action with trust < 0.7, a tainted chain, or a policy obligation", "ESCALATE"),
    (9, "Otherwise", "APPROVE"),
]


def decide(checks: list[Check], *, tier: int, kind: str, trust: float, recent_blocks: int,
           tainted: bool, obligations: list[str]) -> Decision:
    th = get_config()["trust"]["thresholds"]
    by = {c.name: c for c in checks}

    def failed(*names):
        return [by[n] for n in names if n in by and not by[n].passed]

    f = failed("identity")
    if f:
        return Decision("BLOCK", 1, f[0].detail, checks)
    f = failed("chain", "intent")
    if f:
        return Decision("BLOCK", 2, f[0].detail, checks)
    f = failed("policy")
    if f:
        return Decision("BLOCK", 3, f[0].detail, checks)
    f = failed("shield")
    if f:
        return Decision("BLOCK", 4, f[0].detail, checks)
    if "trust" in by and (trust < th["blocked"] or recent_blocks >= get_config()["trust"]["isolate_blocks"]):
        return Decision("ISOLATE", 5, f"trust {trust:.2f} / {recent_blocks} recent blocks", checks)
    f = failed("burst")
    if f:
        return Decision("RESTRICT", 6, f[0].detail, checks)
    if kind == "tool_call" and tier == 2:
        if "trust" in by and trust < th["restricted"]:
            return Decision("BLOCK", 7, f"trust {trust:.2f} < {th['restricted']}: irreversible actions blocked", checks)
        why = []
        if "trust" in by and trust < th["normal"]:
            why.append(f"trust {trust:.2f} < {th['normal']}")
        if tainted:
            why.append("chain carries flagged untrusted data")
        if obligations:
            why.append("policy obligation: " + ", ".join(obligations))
        if why:
            return Decision("ESCALATE", 8, "; ".join(why), checks)
    return Decision("APPROVE", 9, "all checks passed", checks)
