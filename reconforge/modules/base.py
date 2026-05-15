from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding


@dataclass(frozen=True, slots=True)
class ModuleDescriptor:
    name: str
    category: str
    description: str
    active: bool = False


class ReconModule(Protocol):
    name: str
    category: str
    description: str
    active: bool

    async def run(self, target: str, ctx: ReconContext) -> Finding | list[Finding]:
        ...

