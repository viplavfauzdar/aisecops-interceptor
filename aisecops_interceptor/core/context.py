from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from aisecops_interceptor.core.models import InstructionProvenance, RuntimeBudget, RuntimeUsage


@dataclass(slots=True)
class RuntimeContext:
    agent_name: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    prompt: str | None = None
    model_output: str | None = None
    data_classification: str | None = None
    source: str | None = None
    sensitivity_level: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    framework: str = "custom"
    actor: str | None = None
    environment: str = "dev"
    trace_id: str | None = None
    parent_trace_id: str | None = None
    correlation_id: str | None = None
    allowed_capabilities: list[str] | None = None
    provenance: list["InstructionProvenance"] = field(default_factory=list)
    runtime_budget: "RuntimeBudget | None" = None
    runtime_usage: "RuntimeUsage | None" = None
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        from aisecops_interceptor.core.models import InstructionProvenance, RuntimeBudget, RuntimeUsage

        self.provenance = [
            item
            if isinstance(item, InstructionProvenance)
            else InstructionProvenance.from_dict(item)
            for item in self.provenance
        ]
        if isinstance(self.runtime_budget, dict):
            self.runtime_budget = RuntimeBudget(**self.runtime_budget)
        if isinstance(self.runtime_usage, dict):
            self.runtime_usage = RuntimeUsage(**self.runtime_usage)

    def to_tool_call(self) -> "ToolCall":
        from aisecops_interceptor.core.models import ToolCall

        return ToolCall(name=self.tool_name or "", arguments=self.arguments)

    def ensure_trace_id(self) -> str:
        if self.trace_id is None:
            self.trace_id = uuid4().hex
        return self.trace_id
