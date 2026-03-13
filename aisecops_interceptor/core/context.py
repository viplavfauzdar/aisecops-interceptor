from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RuntimeContext:
    agent_name: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    prompt: str | None = None
    data_classification: str | None = None
    source: str | None = None
    sensitivity_level: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    framework: str = "custom"
    actor: str | None = None
    environment: str = "dev"
    correlation_id: str | None = None
    allowed_capabilities: list[str] | None = None
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def to_tool_call(self) -> "ToolCall":
        from aisecops_interceptor.core.models import ToolCall

        return ToolCall(name=self.tool_name or "", arguments=self.arguments)
