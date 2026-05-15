from __future__ import annotations

import asyncio

from .context import ReconContext
from .models import Finding, ReconReport, utc_now
from .scope import ScopeRules, is_ip, is_private_or_special_ip, resolve_addresses, validate_target_safety
from reconforge.modules import MODULES, expand_module_names


async def run_recon(
    target: str,
    module_names: list[str],
    ctx: ReconContext,
    *,
    authorized: bool,
    allow_private: bool,
    scopes: ScopeRules | None = None,
    passive_only: bool = False,
) -> ReconReport:
    selected_names = expand_module_names(module_names)
    selected_modules = [MODULES[name] for name in selected_names]

    if passive_only:
        selected_modules = [module for module in selected_modules if not module.active]
        selected_names = [module.name for module in selected_modules]

    active_modules = [module.name for module in selected_modules if module.active]
    require_auth = ctx.config["safety"]["require_authorization_for_active_modules"]
    if require_auth and active_modules and not authorized and not passive_only:
        joined = ", ".join(active_modules)
        raise PermissionError(
            f"Active modules selected ({joined}). Re-run with --authorized only for assets "
            "you own or are allowed to test."
        )

    host = validate_target_safety(target, allow_private)
    if scopes and (scopes.domains or scopes.cidrs) and not scopes.contains(host):
        raise PermissionError(f"Target {host} is outside the supplied scope.")

    if active_modules and not allow_private and not is_ip(host):
        addresses = await asyncio.to_thread(resolve_addresses, host)
        blocked = [address for address in addresses if is_private_or_special_ip(address)]
        if blocked:
            raise PermissionError(
                f"Target {host} resolves to private, loopback, reserved, or special IP addresses: "
                f"{', '.join(blocked)}. Use --allow-private only for explicitly authorized internal scopes."
            )

    report = ReconReport(
        target=host,
        modules=selected_names,
        started_at=utc_now(),
        metadata={"authorized": authorized, "passive_only": passive_only},
    )

    semaphore = asyncio.Semaphore(int(ctx.config["network"]["max_concurrency"]))

    async def run_one(module) -> list[Finding]:
        async with semaphore:
            try:
                result = await module.run(host, ctx)
                if isinstance(result, list):
                    return result
                return [result]
            except Exception as exc:  # noqa: BLE001 - module boundary reports errors.
                return [
                    Finding(
                        module=module.name,
                        target=host,
                        status="error",
                        error=str(exc),
                    )
                ]

    batches = await asyncio.gather(*(run_one(module) for module in selected_modules))
    for batch in batches:
        report.findings.extend(batch)
    report.completed_at = utc_now()
    return report
