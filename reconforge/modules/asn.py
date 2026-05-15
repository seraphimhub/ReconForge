from __future__ import annotations

import asyncio
import socket

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import is_ip


class ASNModule:
    name = "asn"
    category = "lookup"
    description = "ASN lookup through Team Cymru whois for IP origin and routing metadata."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        timeout = float(ctx.config["network"]["timeout_seconds"])
        query = target if is_ip(target) or target.upper().startswith("AS") else await self._first_ip(target, ctx)
        if not query:
            return Finding(module=self.name, target=target, status="skipped", data={"reason": "No IP address resolved."})

        await ctx.limiter.wait()
        data = await asyncio.to_thread(self._cymru_lookup, query, timeout)
        return Finding(module=self.name, target=target, status="ok", data=data)

    async def _first_ip(self, target: str, ctx: ReconContext) -> str | None:
        def query() -> str | None:
            try:
                answers = ctx.resolver.resolve(target, "A", raise_on_no_answer=False)
                for answer in answers:
                    return answer.to_text()
            except Exception:  # noqa: BLE001 - resolver failure means no ASN lookup.
                return None
            return None

        await ctx.limiter.wait()
        return await asyncio.to_thread(query)

    def _cymru_lookup(self, query: str, timeout: float) -> dict[str, object]:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((f"begin\nverbose\n{query}\nend\n").encode("utf-8"))
            raw = sock.recv(16384).decode("utf-8", errors="replace")

        rows = [line.strip() for line in raw.splitlines() if line.strip()]
        if len(rows) < 2:
            return {"query": query, "raw": raw, "records": []}

        headers = [item.strip().lower().replace(" ", "_") for item in rows[0].split("|")]
        records = []
        for row in rows[1:]:
            values = [item.strip() for item in row.split("|")]
            records.append(dict(zip(headers, values, strict=False)))
        return {"query": query, "records": records, "raw": raw[:5000]}

