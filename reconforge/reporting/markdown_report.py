from __future__ import annotations

from pathlib import Path
from typing import Any

from reconforge.core.models import ReconReport


def render_markdown(report: ReconReport) -> str:
    lines = [
        f"# ReconForge Report: {report.target}",
        "",
        f"- Started: {report.started_at}",
        f"- Completed: {report.completed_at}",
        f"- Modules: {', '.join(report.modules)}",
        "",
        "## Findings",
        "",
    ]

    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.module} - {finding.status}",
                "",
                f"- Target: `{finding.target}`",
                f"- Timestamp: `{finding.timestamp}`",
            ]
        )
        if finding.error:
            lines.append(f"- Error: `{finding.error}`")
        lines.extend(["", "```json", _jsonish(finding.data), "```", ""])
    return "\n".join(lines)


def write_markdown(report: ReconReport, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(report), encoding="utf-8")
    return output


def _jsonish(value: Any) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True, default=str)

