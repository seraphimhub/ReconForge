from __future__ import annotations

import asyncio
import re
import socket

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding


FIELD_PATTERNS = {
    "registrar": re.compile(r"^Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "creation_date": re.compile(r"^Creation Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "updated_date": re.compile(r"^Updated Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "expiry_date": re.compile(r"^(?:Registry Expiry Date|Expiration Date):\s*(.+)$", re.IGNORECASE | re.MULTILINE),
}


class WhoisModule:
    name = "whois"
    category = "lookup"
    description = "WHOIS lookup with IANA referral plus summarized registrar, status, nameserver, and date fields."
    active = False

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        timeout = float(ctx.config["network"]["timeout_seconds"])
        await ctx.limiter.wait()
        data = await asyncio.to_thread(self._lookup, target, timeout)
        return Finding(module=self.name, target=target, status="ok", data=data)

    def _lookup(self, target: str, timeout: float) -> dict[str, object]:
        iana_raw = self._query("whois.iana.org", target, timeout)
        referral = self._extract_referral(iana_raw)
        raw = iana_raw
        server = "whois.iana.org"
        if referral:
            server = referral
            raw = self._query(referral, target, timeout)

        return {
            "server": server,
            "referral": referral,
            "summary": self._parse_summary(raw),
            "raw_excerpt": raw[:5000],
        }

    def _query(self, server: str, query: str, timeout: float) -> str:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 1_000_000:
                    break
        return b"".join(chunks).decode("utf-8", errors="replace")

    def _extract_referral(self, raw: str) -> str | None:
        match = re.search(r"^refer:\s*(\S+)", raw, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else None

    def _parse_summary(self, raw: str) -> dict[str, object]:
        summary: dict[str, object] = {}
        for name, pattern in FIELD_PATTERNS.items():
            match = pattern.search(raw)
            if match:
                summary[name] = match.group(1).strip()

        nameservers = sorted(
            {
                match.group(1).strip().lower().rstrip(".")
                for match in re.finditer(r"^Name Server:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
            }
        )
        statuses = sorted(
            {
                match.group(1).strip()
                for match in re.finditer(r"^Domain Status:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
            }
        )
        if nameservers:
            summary["name_servers"] = nameservers
        if statuses:
            summary["domain_status"] = statuses
        return summary

