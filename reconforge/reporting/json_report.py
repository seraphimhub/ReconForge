from __future__ import annotations

import json
from pathlib import Path

from reconforge.core.models import ReconReport


def render_json(report: ReconReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def write_json(report: ReconReport, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_json(report), encoding="utf-8")
    return output

