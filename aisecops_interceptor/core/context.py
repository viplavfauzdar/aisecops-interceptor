from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


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
    trace_id: str | None = None
    correlation_id: str | None = None
    allowed_capabilities: list[str] | None = None
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def to_tool_call(self) -> "ToolCall":
        from aisecops_interceptor.core.models import ToolCall

        return ToolCall(name=self.tool_name or "", arguments=self.arguments)

    def ensure_trace_id(self) -> str:
        if self.trace_id is None:
            self.trace_id = uuid4().hex
        return self.trace_id
