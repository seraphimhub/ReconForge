from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "network": {
        "timeout_seconds": 10,
        "rate_limit_per_second": 2.0,
        "max_concurrency": 5,
        "user_agent": "ReconForge/0.1 authorized-security-assessment",
    },
    "safety": {
        "allow_private_networks": False,
        "require_authorization_for_active_modules": True,
        "max_targets_per_run": 100,
    },
    "dns": {
        "nameservers": [],
        "record_types": ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"],
    },
    "http": {
        "follow_redirects": True,
        "max_body_bytes": 250000,
        "fetch_robots": True,
    },
    "tls": {
        "default_port": 443,
    },
    "passive_sources": {
        "certificate_transparency": {
            "enabled": True,
            "max_results": 200,
        },
        "geolocation": {
            "enabled": True,
            "provider": "ipwhois",
        },
        "reverse_ip": {
            "enabled": False,
            "endpoint": "",
            "query_param": "q",
            "api_key_env": "",
            "api_key_header": "Authorization",
        },
        "reverse_whois": {
            "enabled": False,
            "endpoint": "",
            "query_param": "q",
            "api_key_env": "",
            "api_key_header": "Authorization",
        },
    },
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        return deepcopy(DEFAULT_CONFIG)

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError("Config root must be a mapping")
    return deep_merge(DEFAULT_CONFIG, loaded)

