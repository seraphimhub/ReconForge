from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from reconforge.core.config import load_config
from reconforge.core.context import build_context
from reconforge.core.runner import run_recon
from reconforge.core.scope import ScopeRules
from reconforge.modules import DEFAULT_MODULES, MODULES, expand_module_names
from reconforge.reporting.json_report import render_json, write_json
from reconforge.reporting.markdown_report import render_markdown, write_markdown


app = typer.Typer(
    add_completion=False,
    help="ReconForge: modular recon CLI for authorized security assessment.",
)
console = Console()


@app.command("list-modules")
def list_modules() -> None:
    """Show available modules."""
    table = Table(title="ReconForge Modules")
    table.add_column("Name", style="cyan")
    table.add_column("Category")
    table.add_column("Active")
    table.add_column("Description")
    for module in MODULES.values():
        table.add_row(module.name, module.category, "yes" if module.active else "no", module.description)
    console.print(table)


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Domain, IP address, or URL to assess.")],
    modules: Annotated[
        str,
        typer.Option(
            "--modules",
            "-m",
            help="Comma-separated module list. Use default or all.",
        ),
    ] = ",".join(DEFAULT_MODULES),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="YAML config path."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output report path. Defaults to stdout."),
    ] = None,
    report_format: Annotated[
        str,
        typer.Option("--format", "-f", help="json or md."),
    ] = "json",
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Confirm you own the target or have explicit permission for selected active modules.",
        ),
    ] = False,
    allow_private: Annotated[
        bool,
        typer.Option("--allow-private", help="Allow private, loopback, reserved, or special IP targets."),
    ] = False,
    passive_only: Annotated[
        bool,
        typer.Option("--passive-only", help="Drop active modules such as HTTP and TLS."),
    ] = False,
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", help="Allowed domain or CIDR. Can be repeated."),
    ] = None,
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope-file", help="File with one allowed domain or CIDR per line."),
    ] = None,
) -> None:
    """Run a recon workflow."""
    try:
        selected = expand_module_names([modules])
        scope_values = list(scope or [])
        if scope_file:
            scope_values.extend(
                line.strip()
                for line in scope_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        rules = ScopeRules.from_values(scope_values)
        cfg = load_config(config)
        effective_allow_private = allow_private or bool(cfg["safety"].get("allow_private_networks"))
        report = asyncio.run(
            _scan_async(
                target=target,
                selected=selected,
                cfg=cfg,
                authorized=authorized,
                allow_private=effective_allow_private,
                passive_only=passive_only,
                scopes=rules,
            )
        )
        _emit(report, report_format, output)
    except Exception as exc:  # noqa: BLE001 - CLI boundary.
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command("scan-file")
def scan_file(
    target_file: Annotated[Path, typer.Argument(help="File with one target per line.")],
    modules: Annotated[
        str,
        typer.Option("--modules", "-m", help="Comma-separated module list. Use default or all."),
    ] = ",".join(DEFAULT_MODULES),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="YAML config path."),
    ] = None,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-o", help="Directory for per-target reports."),
    ] = Path("reports"),
    report_format: Annotated[
        str,
        typer.Option("--format", "-f", help="json or md."),
    ] = "json",
    authorized: Annotated[
        bool,
        typer.Option("--authorized", help="Confirm permission for selected active modules."),
    ] = False,
    allow_private: Annotated[
        bool,
        typer.Option("--allow-private", help="Allow private, loopback, reserved, or special IP targets."),
    ] = False,
    passive_only: Annotated[
        bool,
        typer.Option("--passive-only", help="Drop active modules such as HTTP and TLS."),
    ] = False,
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", help="Allowed domain or CIDR. Can be repeated."),
    ] = None,
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope-file", help="File with one allowed domain or CIDR per line."),
    ] = None,
) -> None:
    """Run recon for multiple targets and write one report per target."""
    try:
        cfg = load_config(config)
        targets = _read_lines(target_file)
        max_targets = int(cfg["safety"]["max_targets_per_run"])
        if len(targets) > max_targets:
            raise ValueError(f"Target file has {len(targets)} targets, above max_targets_per_run={max_targets}.")

        selected = expand_module_names([modules])
        scope_values = list(scope or [])
        if scope_file:
            scope_values.extend(_read_lines(scope_file))
        rules = ScopeRules.from_values(scope_values)
        effective_allow_private = allow_private or bool(cfg["safety"].get("allow_private_networks"))
        reports, errors = asyncio.run(
            _scan_many_async(
                targets=targets,
                selected=selected,
                cfg=cfg,
                authorized=authorized,
                allow_private=effective_allow_private,
                passive_only=passive_only,
                scopes=rules,
            )
        )

        for report in reports:
            suffix = "md" if report_format.lower() in {"md", "markdown"} else "json"
            path = output_dir / f"{_safe_filename(report.target)}.{suffix}"
            _emit(report, report_format, path)

        if errors:
            for target, error in errors:
                console.print(f"[yellow]skipped {target}:[/yellow] {error}")
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - CLI boundary.
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


async def _scan_async(
    *,
    target: str,
    selected: list[str],
    cfg: dict,
    authorized: bool,
    allow_private: bool,
    passive_only: bool,
    scopes: ScopeRules,
):
    async with build_context(cfg) as ctx:
        return await run_recon(
            target,
            selected,
            ctx,
            authorized=authorized,
            allow_private=allow_private,
            scopes=scopes,
            passive_only=passive_only,
        )


async def _scan_many_async(
    *,
    targets: list[str],
    selected: list[str],
    cfg: dict,
    authorized: bool,
    allow_private: bool,
    passive_only: bool,
    scopes: ScopeRules,
):
    reports = []
    errors = []
    async with build_context(cfg) as ctx:
        for target in targets:
            try:
                reports.append(
                    await run_recon(
                        target,
                        selected,
                        ctx,
                        authorized=authorized,
                        allow_private=allow_private,
                        scopes=scopes,
                        passive_only=passive_only,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - keep batch jobs moving.
                errors.append((target, str(exc)))
    return reports, errors


def _emit(report, report_format: str, output: Path | None) -> None:
    normalized = report_format.lower()
    if normalized not in {"json", "md", "markdown"}:
        raise ValueError("--format must be json or md")

    if output is None:
        console.print(render_markdown(report) if normalized in {"md", "markdown"} else render_json(report))
        return

    if normalized == "json":
        path = write_json(report, output)
    else:
        path = write_markdown(report, output)
    console.print(f"[green]wrote report:[/green] {path}")


def _read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_") or "target"
