from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding
from reconforge.core.scope import extract_host


class TLSModule:
    name = "tls"
    category = "active"
    description = "TLS certificate, issuer, SAN, cipher, protocol, and expiration metadata."
    active = True

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        host = extract_host(target)
        port = int(ctx.config["tls"]["default_port"])
        await ctx.limiter.wait()
        data = await asyncio.to_thread(self._inspect, host, port, float(ctx.config["network"]["timeout_seconds"]))
        return Finding(module=self.name, target=host, status="ok", data=data)

    def _inspect(self, host: str, port: int, timeout: float) -> dict[str, object]:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                not_after = cert.get("notAfter")
                expires_at = self._parse_cert_time(not_after)
                return {
                    "host": host,
                    "port": port,
                    "protocol": tls_sock.version(),
                    "cipher": tls_sock.cipher(),
                    "subject": self._name_tuple_to_dict(cert.get("subject", [])),
                    "issuer": self._name_tuple_to_dict(cert.get("issuer", [])),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": not_after,
                    "expires_at_utc": expires_at.isoformat() if expires_at else None,
                    "expired": bool(expires_at and expires_at < datetime.now(timezone.utc)),
                    "subject_alt_names": [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"],
                }

    def _parse_cert_time(self, value: str | None) -> datetime | None:
        if not value:
            return None
        seconds = ssl.cert_time_to_seconds(value)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    def _name_tuple_to_dict(self, value: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
        output: dict[str, str] = {}
        for group in value:
            for key, item in group:
                output[key] = item
        return output

