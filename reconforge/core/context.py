from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Any

import dns.resolver
import httpx

from .rate_limiter import AsyncRateLimiter


@dataclass(slots=True)
class ReconContext:
    config: dict[str, Any]
    client: httpx.AsyncClient
    resolver: dns.resolver.Resolver
    limiter: AsyncRateLimiter


@asynccontextmanager
async def build_context(config: dict[str, Any]) -> AsyncIterator[ReconContext]:
    network = config["network"]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = float(network["timeout_seconds"])
    resolver.timeout = float(network["timeout_seconds"])
    if config["dns"].get("nameservers"):
        resolver.nameservers = list(config["dns"]["nameservers"])

    headers = {"User-Agent": network["user_agent"]}
    timeout = httpx.Timeout(float(network["timeout_seconds"]))
    async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
        yield ReconContext(
            config=config,
            client=client,
            resolver=resolver,
            limiter=AsyncRateLimiter(float(network["rate_limit_per_second"])),
        )

