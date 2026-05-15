from __future__ import annotations

import asyncio

import dns.exception
import dns.reversename
import dns.resolver

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import is_ip


class DNSModule:
    name = "dns"
    category = "lookup"
    description = "DNS lookup for A, AAAA, MX, NS, TXT, CAA, SOA, and PTR records."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        data: dict[str, object] = {"records": {}}
        record_types = ctx.config["dns"]["record_types"]

        if is_ip(target):
            data["ptr"] = await self._reverse_dns(target, ctx)
        else:
            for record_type in record_types:
                data["records"][record_type] = await self._resolve(target, record_type, ctx)

        return Finding(module=self.name, target=target, status="ok", data=data)

    async def _resolve(self, target: str, record_type: str, ctx: ReconContext) -> list[str]:
        def query() -> list[str]:
            try:
                answers = ctx.resolver.resolve(target, record_type, raise_on_no_answer=False)
                return sorted({answer.to_text().strip('"') for answer in answers})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return []
            except dns.exception.Timeout:
                return ["timeout"]

        await ctx.limiter.wait()
        return await asyncio.to_thread(query)

    async def _reverse_dns(self, target: str, ctx: ReconContext) -> list[str]:
        def query() -> list[str]:
            try:
                reverse_name = dns.reversename.from_address(target)
                answers = ctx.resolver.resolve(reverse_name, "PTR", raise_on_no_answer=False)
                return sorted({answer.to_text().rstrip(".") for answer in answers})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return []
            except dns.exception.Timeout:
                return ["timeout"]

        await ctx.limiter.wait()
        return await asyncio.to_thread(query)

