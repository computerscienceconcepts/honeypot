from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict


class RateLimiter:
    """Fixed-window per-IP rate limiter.

    Allows up to `max_events_per_minute` connection events in the last 60s
    for each unique IP. Uses an in-memory deque per IP for simplicity.
    """

    def __init__(self, max_events_per_minute: int) -> None:
        self.max_events_per_minute = max_events_per_minute
        self._ip_to_events: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        events = self._ip_to_events[ip]
        # Evict old timestamps
        while events and events[0] < window_start:
            events.popleft()

        if len(events) >= self.max_events_per_minute:
            return False

        events.append(now)
        return True


