from __future__ import annotations

import asyncio
import ipaddress

import dns.exception
import dns.resolver
import httpx

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import is_ip


class IPLookupModule:
    name = "ip"
    category = "lookup"
    description = "IP lookup for resolved addresses, PTR, RDAP, and local address classification."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        ips = [target] if is_ip(target) else await self._resolve_ips(target, ctx)
        data = {"addresses": []}
        for address in ips:
            data["addresses"].append(
                {
                    "ip": address,
                    "classification": self._classification(address),
                    "ptr": await self._ptr(address, ctx),
                    "rdap": await self._rdap(address, ctx),
                }
            )
        return Finding(module=self.name, target=target, status="ok", data=data)

    async def _resolve_ips(self, target: str, ctx: ReconContext) -> list[str]:
        def query(record_type: str) -> list[str]:
            try:
                answers = ctx.resolver.resolve(target, record_type, raise_on_no_answer=False)
                return [answer.to_text() for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return []

        await ctx.limiter.wait()
        ipv4 = await asyncio.to_thread(query, "A")
        await ctx.limiter.wait()
        ipv6 = await asyncio.to_thread(query, "AAAA")
        return sorted(set(ipv4 + ipv6))

    def _classification(self, address: str) -> dict[str, bool | str]:
        ip = ipaddress.ip_address(address)
        return {
            "version": str(ip.version),
            "is_global": ip.is_global,
            "is_private": ip.is_private,
            "is_loopback": ip.is_loopback,
            "is_link_local": ip.is_link_local,
            "is_multicast": ip.is_multicast,
            "is_reserved": ip.is_reserved,
        }

    async def _ptr(self, address: str, ctx: ReconContext) -> list[str]:
        def query() -> list[str]:
            try:
                import dns.reversename

                reverse_name = dns.reversename.from_address(address)
                answers = ctx.resolver.resolve(reverse_name, "PTR", raise_on_no_answer=False)
                return sorted({answer.to_text().rstrip(".") for answer in answers})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return []

        await ctx.limiter.wait()
        return await asyncio.to_thread(query)

    async def _rdap(self, address: str, ctx: ReconContext) -> dict[str, object]:
        url = f"https://rdap.org/ip/{address}"
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(url)
            if response.status_code >= 400:
                return {"url": url, "ok": False, "status_code": response.status_code}
            payload = response.json()
            return {
                "url": url,
                "ok": True,
                "handle": payload.get("handle"),
                "name": payload.get("name"),
                "type": payload.get("type"),
                "country": payload.get("country"),
                "start_address": payload.get("startAddress"),
                "end_address": payload.get("endAddress"),
                "parent_handle": payload.get("parentHandle"),
                "events": payload.get("events", []),
                "links": payload.get("links", []),
                "entities": payload.get("entities", [])[:10],
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"url": url, "ok": False, "error": str(exc)}

