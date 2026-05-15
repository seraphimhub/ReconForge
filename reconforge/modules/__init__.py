from __future__ import annotations

from reconforge.modules.asn import ASNModule
from reconforge.modules.dns import DNSModule
from reconforge.modules.domain import DomainModule
from reconforge.modules.geo import GeolocationModule
from reconforge.modules.http import HTTPModule
from reconforge.modules.ip import IPLookupModule
from reconforge.modules.reverse import ReverseLookupModule
from reconforge.modules.tls import TLSModule
from reconforge.modules.whois import WhoisModule


MODULES = {
    "domain": DomainModule(),
    "dns": DNSModule(),
    "whois": WhoisModule(),
    "http": HTTPModule(),
    "tls": TLSModule(),
    "ip": IPLookupModule(),
    "asn": ASNModule(),
    "geo": GeolocationModule(),
    "reverse": ReverseLookupModule(),
}

DEFAULT_MODULES = ["domain", "dns", "whois", "ip", "asn", "geo", "reverse"]
ALL_MODULES = list(MODULES)


def expand_module_names(module_names: list[str]) -> list[str]:
    expanded: list[str] = []
    for raw_name in module_names:
        for name in raw_name.split(","):
            clean = name.strip().lower()
            if not clean:
                continue
            if clean == "all":
                expanded.extend(ALL_MODULES)
            elif clean == "default":
                expanded.extend(DEFAULT_MODULES)
            elif clean in MODULES:
                expanded.append(clean)
            else:
                raise ValueError(f"Unknown module: {clean}")
    return list(dict.fromkeys(expanded))

