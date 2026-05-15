from __future__ import annotations

import os
from urllib.parse import urlencode

import httpx

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import is_ip


class ReverseLookupModule:
    name = "reverse"
    category = "passive"
    description = "Reverse DNS, reverse IP provider hook, CT sibling domains, and configurable reverse WHOIS provider hook."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        data: dict[str, object] = {}
        if is_ip(target):
            data["reverse_ip"] = await self._configured_provider("reverse_ip", target, ctx)
        else:
            data["certificate_transparency_names"] = await self._ct_names(target, ctx)
            data["reverse_whois"] = await self._configured_provider("reverse_whois", target, ctx)
        return Finding(module=self.name, target=target, status="ok", data=data)

    async def _ct_names(self, domain: str, ctx: ReconContext) -> dict[str, object]:
        ct_config = ctx.config["passive_sources"]["certificate_transparency"]
        if not ct_config.get("enabled"):
            return {"enabled": False}

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(url)
            if response.status_code >= 400:
                return {"url": url, "ok": False, "status_code": response.status_code}
            payload = response.json()
            names: set[str] = set()
            for item in payload:
                for name in str(item.get("name_value", "")).splitlines():
                    clean = name.strip().lower().lstrip("*.").rstrip(".")
                    if clean.endswith(domain):
                        names.add(clean)
            return {
                "url": url,
                "ok": True,
                "count": len(names),
                "names": sorted(names)[: int(ct_config["max_results"])],
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"url": url, "ok": False, "error": str(exc)}

    async def _configured_provider(self, provider_name: str, query: str, ctx: ReconContext) -> dict[str, object]:
        provider = ctx.config["passive_sources"].get(provider_name, {})
        if not provider.get("enabled"):
            return {
                "enabled": False,
                "reason": (
                    f"{provider_name} requires a configured external provider. "
                    "Set endpoint, query_param, and optional API key env in configs/default.yaml."
                ),
            }

        endpoint = str(provider.get("endpoint", "")).strip()
        if not endpoint:
            return {"enabled": True, "ok": False, "error": "Provider endpoint is empty."}

        headers = {}
        api_key_env = str(provider.get("api_key_env", "")).strip()
        if api_key_env:
            api_key = os.getenv(api_key_env)
            if not api_key:
                return {"enabled": True, "ok": False, "error": f"Missing API key env var: {api_key_env}"}
            headers[str(provider.get("api_key_header", "Authorization"))] = api_key

        params = urlencode({str(provider.get("query_param", "q")): query})
        separator = "&" if "?" in endpoint else "?"
        url = f"{endpoint}{separator}{params}"
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(url, headers=headers)
            content_type = response.headers.get("content-type", "")
            if "json" in content_type:
                payload: object = response.json()
            else:
                payload = response.text[:20000]
            return {"url": url, "ok": response.status_code < 400, "status_code": response.status_code, "result": payload}
        except (httpx.HTTPError, ValueError) as exc:
            return {"url": url, "ok": False, "error": str(exc)}

