"""Modules 5 and 6 - burst limiter (synchronous) and behavioural trust engine.

Trust formula (closes Gap 3, reputation laundering):
  violation of severity s:   T <- T * (1 - s);  T_v = T;  t_v = now
  good action a at time t:   T <- min( T + eta0 / (1 + n_W(t)) * w_a * (1 - T),  C(t) )
  recovery ceiling:          C(t) = T_v + (1 - T_v) * (1 - exp(-(t - t_v) / tau))
- w_a: cheap actions earn little (read 0.01 ... tier-2 write 0.05)
- n_W: good actions in the last W seconds - packing actions together earns less each
- C(t): grows with TIME, not with the number of actions -> bursts cannot launder trust
A LinearTrust (exponential moving average) is kept alongside for the comparison graph.
"""
from __future__ import annotations

import math
import threading
from collections import defaultdict, deque
from dataclasses import dataclass

from backend.common import CLOCK
from backend.config import get_config

AGENTS = ["orchestrator", "planner", "researcher", "executor", "auditor"]


# ----------------------------------------------------------------------------- burst limiter
class BurstLimiter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: dict[tuple[str, str], deque] = defaultdict(deque)
        self.amounts: dict[str, deque] = defaultdict(deque)
        self.cooldown_until: dict[str, float] = {}

    def reset(self) -> None:
        with self.lock:
            self.events.clear()
            self.amounts.clear()
            self.cooldown_until.clear()

    def in_cooldown(self, agent: str) -> bool:
        return self.cooldown_until.get(agent, 0) > CLOCK.now()

    def check(self, agent: str, kind: str, amount: float = 0.0) -> tuple[bool, str]:
        """kind = read | write. Records the attempt and says whether it is within limits."""
        cfg = get_config()["burst"]
        now = CLOCK.now()
        with self.lock:
            if self.cooldown_until.get(agent, 0) > now and kind == "write":
                return False, f"agent in burst cooldown for {self.cooldown_until[agent] - now:.0f}s more"
            q = self.events[(agent, kind)]
            while q and q[0] < now - cfg["window_s"]:
                q.popleft()
            q.append(now)
            limit = cfg["max_reads"] if kind == "read" else cfg["max_writes"]
            if len(q) > limit:
                self.cooldown_until[agent] = now + cfg["cooldown_s"]
                return False, f"{len(q)} {kind}s in {cfg['window_s']}s exceeds limit of {limit}"
            if amount > 0:
                a = self.amounts[agent]
                while a and a[0][0] < now - cfg["amount_window_s"]:
                    a.popleft()
                total = sum(x for _, x in a) + amount
                if total > cfg["max_amount"]:
                    self.cooldown_until[agent] = now + cfg["cooldown_s"]
                    return False, f"Rs {total:,.0f} moved in {cfg['amount_window_s']}s exceeds velocity limit"
                a.append((now, amount))
        return True, "within rate limits"


# ----------------------------------------------------------------------------- trust engine
@dataclass
class AgentTrust:
    T: float
    T_v: float
    t_v: float | None
    good: deque
    blocks: deque


class TrustEngine:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        cfg = get_config()["trust"]
        with self.lock:
            self.state = {a: AgentTrust(cfg["initial"], cfg["initial"], None, deque(), deque()) for a in AGENTS}
            self.history: list[dict] = [{"ts": CLOCK.now(), "agent": a, "score": cfg["initial"], "event": "init"} for a in AGENTS]

    def _st(self, agent: str) -> AgentTrust:
        if agent not in self.state:
            cfg = get_config()["trust"]
            self.state[agent] = AgentTrust(cfg["initial"], cfg["initial"], None, deque(), deque())
        return self.state[agent]

    def score(self, agent: str) -> float:
        with self.lock:
            return round(self._st(agent).T, 4)

    def ceiling(self, agent: str, now: float | None = None) -> float:
        cfg = get_config()["trust"]
        st = self._st(agent)
        if st.t_v is None:
            return 1.0
        now = CLOCK.now() if now is None else now
        return st.T_v + (1 - st.T_v) * (1 - math.exp(-(now - st.t_v) / cfg["tau_s"]))

    def penalize(self, agent: str, severity: str, reason: str) -> float:
        cfg = get_config()["trust"]
        s = cfg["severity"].get(severity, 0.4)
        now = CLOCK.now()
        with self.lock:
            st = self._st(agent)
            st.T = st.T * (1 - s)
            st.T_v, st.t_v = st.T, now
            self.history.append({"ts": now, "agent": agent, "score": round(st.T, 4), "event": f"violation({severity}): {reason}"[:160]})
            return st.T

    def record_block(self, agent: str) -> int:
        cfg = get_config()["trust"]
        now = CLOCK.now()
        with self.lock:
            q = self._st(agent).blocks
            q.append(now)
            while q and q[0] < now - cfg["isolate_window_s"]:
                q.popleft()
            return len(q)

    def recent_blocks(self, agent: str) -> int:
        cfg = get_config()["trust"]
        now = CLOCK.now()
        with self.lock:
            return sum(1 for t in self._st(agent).blocks if t >= now - cfg["isolate_window_s"])

    def reward(self, agent: str, weight_key: str) -> float:
        cfg = get_config()["trust"]
        now = CLOCK.now()
        with self.lock:
            st = self._st(agent)
            while st.good and st.good[0] < now - cfg["window_s"]:
                st.good.popleft()
            n_w = len(st.good)
            eta = cfg["eta0"] / (1 + n_w)
            w = cfg["weights"].get(weight_key, 0.01)
            new = st.T + eta * w * (1 - st.T)
            st.T = min(new, self.ceiling(agent, now))
            st.good.append(now)
            self.history.append({"ts": now, "agent": agent, "score": round(st.T, 4), "event": f"good:{weight_key}"})
            return st.T

    def set_score(self, agent: str, value: float, reason: str) -> None:
        with self.lock:
            st = self._st(agent)
            st.T = value
            st.T_v, st.t_v = value, CLOCK.now()
            self.history.append({"ts": CLOCK.now(), "agent": agent, "score": value, "event": reason})

    def snapshot(self) -> dict:
        with self.lock:
            return {a: {"score": round(st.T, 4), "ceiling": round(self.ceiling(a), 4),
                        "recent_blocks": len(st.blocks)} for a, st in self.state.items()}


class LinearTrust:
    """What existing reputation systems do: exponential moving average, T <- a*T + (1-a)*outcome."""

    def __init__(self, initial: float = 0.75, alpha: float = 0.9) -> None:
        self.T, self.alpha = initial, alpha

    def violation(self, severity_value: float) -> float:
        self.T = self.T * (1 - severity_value)
        return self.T

    def good(self) -> float:
        self.T = self.alpha * self.T + (1 - self.alpha) * 1.0
        return self.T


# ----------------------------------------------------------------------------- anomaly detector (async)
class AnomalyDetector:
    """EWMA baseline per agent of the gap between actions and of transfer amounts.
    A z-score above 3 (after a warm-up of 10 events) is reported as a low-severity anomaly."""

    def __init__(self, alpha: float = 0.2, warmup: int = 10) -> None:
        self.alpha, self.warmup = alpha, warmup
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.stats: dict[str, dict] = {}

    def _upd(self, st: dict, key: str, x: float) -> float:
        m, v = st.get(key + "_m"), st.get(key + "_v", 0.0)
        if m is None:
            st[key + "_m"], st[key + "_v"] = x, 0.0
            return 0.0
        # floor on the spread (0.5 in log space ~ a 1.65x change) so perfectly regular
        # behaviour does not turn tiny timing jitter into a huge z-score
        z = abs(x - m) / max(math.sqrt(v), 0.5)
        d = x - m
        st[key + "_m"] = m + self.alpha * d
        st[key + "_v"] = (1 - self.alpha) * (v + self.alpha * d * d)
        return z

    def observe(self, agent: str, amount: float = 0.0) -> str | None:
        now = CLOCK.now()
        with self.lock:
            st = self.stats.setdefault(agent, {"n": 0, "last": None})
            st["n"] += 1
            gap = (now - st["last"]) if st["last"] else None
            st["last"] = now
            zs = []
            if gap is not None:
                zs.append(("action gap", self._upd(st, "gap", math.log1p(gap))))
            if amount > 0:
                zs.append(("amount", self._upd(st, "amt", math.log1p(amount))))
            if st["n"] <= self.warmup:
                return None
            for name, z in zs:
                if z > 3:
                    return f"{name} z-score {z:.1f} above 3"
        return None
