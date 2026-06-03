from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aisecops_interceptor.core.models import InstructionProvenance


@dataclass(slots=True)
class MCPInvocation:
    session_id: str
    client_id: str
    server_name: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    provenance: list[InstructionProvenance] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        self.provenance = [
            item
            if isinstance(item, InstructionProvenance)
            else InstructionProvenance.from_dict(item)
            for item in self.provenance
        ]


@dataclass(slots=True)
class MCPDecision:
    allowed: bool
    reason: str
    risk_level: str
    capability: str
    trace_id: str
