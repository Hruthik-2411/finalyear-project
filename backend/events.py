"""In-process event bus. The gateway publishes; the dashboard reads over WebSocket/polling."""
from __future__ import annotations

import threading
from collections import deque

from backend.common import CLOCK


class EventBus:
    def __init__(self, maxlen: int = 3000) -> None:
        self.lock = threading.Lock()
        self.events: deque = deque(maxlen=maxlen)
        self.seq = 0

    def publish(self, type_: str, data: dict) -> None:
        with self.lock:
            self.seq += 1
            self.events.append({"id": self.seq, "ts": CLOCK.iso(), "type": type_, "data": data})

    def since(self, last_id: int, limit: int = 500) -> list[dict]:
        with self.lock:
            return [e for e in self.events if e["id"] > last_id][:limit]

    def clear(self) -> None:
        with self.lock:
            self.events.clear()


BUS = EventBus()
