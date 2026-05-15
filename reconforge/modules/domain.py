from __future__ import annotations

import httpx

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import is_ip


class DomainModule:
    name = "domain"
    category = "passive"
    description = "Domain RDAP and certificate transparency discovery."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        if is_ip(target):
            return Finding(
                module=self.name,
                target=target,
                status="skipped",
                data={"reason": "Domain module expects a domain name, not an IP address."},
            )

        data = {
            "rdap": await self._rdap(target, ctx),
            "certificate_transparency": await self._certificate_transparency(target, ctx),
        }
        return Finding(module=self.name, target=target, status="ok", data=data)

    async def _rdap(self, domain: str, ctx: ReconContext) -> dict[str, object]:
        url = f"https://rdap.org/domain/{domain}"
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
                "ldh_name": payload.get("ldhName"),
                "status": payload.get("status", []),
                "events": payload.get("events", []),
                "nameservers": payload.get("nameservers", []),
                "entities": self._summarize_entities(payload.get("entities", [])),
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"url": url, "ok": False, "error": str(exc)}

    async def _certificate_transparency(self, domain: str, ctx: ReconContext) -> dict[str, object]:
        ct_config = ctx.config["passive_sources"]["certificate_transparency"]
        if not ct_config.get("enabled"):
            return {"enabled": False}

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        max_results = int(ct_config["max_results"])
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(url)
            if response.status_code >= 400:
                return {"url": url, "ok": False, "status_code": response.status_code}
            payload = response.json()
            names: set[str] = set()
            for item in payload:
                raw_name = str(item.get("name_value", ""))
                for name in raw_name.splitlines():
                    clean = name.strip().lower().lstrip("*.").rstrip(".")
                    if clean.endswith(domain):
                        names.add(clean)
            return {"url": url, "ok": True, "count": len(names), "names": sorted(names)[:max_results]}
        except (httpx.HTTPError, ValueError) as exc:
            return {"url": url, "ok": False, "error": str(exc)}

    def _summarize_entities(self, entities: list[dict[str, object]]) -> list[dict[str, object]]:
        output: list[dict[str, object]] = []
        for entity in entities[:20]:
            output.append(
                {
                    "handle": entity.get("handle"),
                    "roles": entity.get("roles", []),
                    "public_ids": entity.get("publicIds", []),
                }
            )
        return output

