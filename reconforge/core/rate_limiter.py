from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    """Small async token-style limiter for polite network use."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate_per_second = max(rate_per_second, 0.1)
        self._lock = asyncio.Lock()
        self._last_run = 0.0

    async def wait(self) -> None:
        async with self._lock:
            interval = 1.0 / self.rate_per_second
            now = time.monotonic()
            sleep_for = self._last_run + interval - now
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last_run = time.monotonic()

