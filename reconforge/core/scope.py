from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit


HOST_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")


def extract_host(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Target is empty")

    if "://" in value:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
    else:
        host = value.split("/")[0].split("?")[0].strip("[]")
        if "@" in host:
            host = host.rsplit("@", 1)[-1]
        if ":" in host and not _looks_like_ipv6(host):
            host = host.split(":", 1)[0]

    host = host.strip().lower().rstrip(".")
    if not host or not HOST_RE.match(host):
        raise ValueError(f"Invalid target host: {target}")
    return host


def _looks_like_ipv6(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return ":" in value
    except ValueError:
        return False


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_or_special_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@dataclass(slots=True)
class ScopeRules:
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)

    @classmethod
    def from_values(cls, values: list[str]) -> "ScopeRules":
        domains: list[str] = []
        cidrs: list[str] = []
        for raw in values:
            item = raw.strip().lower().rstrip(".")
            if not item:
                continue
            try:
                ipaddress.ip_network(item, strict=False)
                cidrs.append(item)
            except ValueError:
                domains.append(item.lstrip("*."))
        return cls(domains=domains, cidrs=cidrs)

    def contains(self, target: str) -> bool:
        host = extract_host(target)
        if is_ip(host):
            ip = ipaddress.ip_address(host)
            return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in self.cidrs)

        return any(host == domain or host.endswith(f".{domain}") for domain in self.domains)


def validate_target_safety(target: str, allow_private: bool) -> str:
    host = extract_host(target)
    if is_ip(host) and is_private_or_special_ip(host) and not allow_private:
        raise ValueError(
            "Private, loopback, reserved, or special IP targets are blocked by default. "
            "Use --allow-private only for networks you are explicitly authorized to assess."
        )
    return host


def resolve_addresses(host: str) -> list[str]:
    addresses: set[str] = set()
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        addresses.add(item[4][0])
    return sorted(addresses)
