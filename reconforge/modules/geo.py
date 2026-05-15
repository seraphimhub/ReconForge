from __future__ import annotations

import asyncio
import ipaddress

import dns.exception
import dns.resolver
import httpx

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import is_ip


class GeolocationModule:
    name = "geo"
    category = "passive"
    description = "IP geolocation lookup with local classification and optional ipwho.is enrichment."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        ips = [target] if is_ip(target) else await self._resolve_ips(target, ctx)
        data = {"addresses": []}
        for address in ips:
            item = {"ip": address, "classification": self._classification(address)}
            item["geolocation"] = await self._ipwhois(address, ctx)
            data["addresses"].append(item)
        return Finding(module=self.name, target=target, status="ok", data=data)

    async def _resolve_ips(self, target: str, ctx: ReconContext) -> list[str]:
        def query() -> list[str]:
            try:
                answers = ctx.resolver.resolve(target, "A", raise_on_no_answer=False)
                return [answer.to_text() for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return []

        await ctx.limiter.wait()
        return await asyncio.to_thread(query)

    def _classification(self, address: str) -> dict[str, bool | str]:
        ip = ipaddress.ip_address(address)
        return {
            "version": str(ip.version),
            "is_global": ip.is_global,
            "is_private": ip.is_private,
            "is_reserved": ip.is_reserved,
        }

    async def _ipwhois(self, address: str, ctx: ReconContext) -> dict[str, object]:
        geo_config = ctx.config["passive_sources"]["geolocation"]
        if not geo_config.get("enabled"):
            return {"enabled": False}
        if not ipaddress.ip_address(address).is_global:
            return {"ok": False, "reason": "Geolocation skipped for non-global IP."}

        url = f"https://ipwho.is/{address}"
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(url)
            if response.status_code >= 400:
                return {"url": url, "ok": False, "status_code": response.status_code}
            payload = response.json()
            return {
                "url": url,
                "ok": bool(payload.get("success", True)),
                "country": payload.get("country"),
                "country_code": payload.get("country_code"),
                "region": payload.get("region"),
                "city": payload.get("city"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "timezone": payload.get("timezone"),
                "connection": payload.get("connection"),
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"url": url, "ok": False, "error": str(exc)}

