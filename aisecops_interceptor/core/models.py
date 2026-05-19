from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, Field

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.planning.models import ExecutionPlan as StructuredExecutionPlan


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InterceptionRequest:
    context: RuntimeContext
    tool_registry: dict[str, Callable[..., Any]]
    approval_id: str | None = None
    dry_run: bool = False


@dataclass(slots=True)
class InstructionProvenance:
    source_type: str
    trust_level: str
    source_name: str | None = None
    source_hash: str | None = None
    origin_uri: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_name": self.source_name,
            "source_hash": self.source_hash,
            "origin_uri": self.origin_uri,
            "trust_level": self.trust_level,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InstructionProvenance":
        return cls(
            source_type=str(data["source_type"]),
            source_name=str(data["source_name"]) if data.get("source_name") is not None else None,
            source_hash=str(data["source_hash"]) if data.get("source_hash") is not None else None,
            origin_uri=str(data["origin_uri"]) if data.get("origin_uri") is not None else None,
            trust_level=str(data["trust_level"]),
            metadata=dict(data["metadata"]) if isinstance(data.get("metadata"), dict) else {},
        )


@dataclass(slots=True)
class ExecutionPlan:
    context: RuntimeContext
    tool_registry: dict[str, Callable[..., Any]]
    execution_plan_id: str = field(default_factory=lambda: uuid4().hex)
    structured_plan: StructuredExecutionPlan | None = None
    approval_id: str | None = None
    dry_run: bool = False
    provenance: list[InstructionProvenance] = field(default_factory=list)
    trace: DecisionTrace | None = None

    def __post_init__(self) -> None:
        self.provenance = [
            item
            if isinstance(item, InstructionProvenance)
            else InstructionProvenance.from_dict(item)
            for item in self.provenance
        ]

    def has_provenance_trust(self, *trust_levels: str) -> bool:
        normalized = {value.lower() for value in trust_levels}
        return any(item.trust_level.lower() in normalized for item in self.provenance)

    def has_provenance_source_type(self, *source_types: str) -> bool:
        normalized = {value.lower() for value in source_types}
        return any(item.source_type.lower() in normalized for item in self.provenance)


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    matched_rule: str | None = None
    risk_level: str = "low"
    requires_approval: bool = False


@dataclass(slots=True)
class CapabilityDefinition:
    tools: tuple[str, ...]
    description: str | None = None
    risk: str | None = None


@dataclass(slots=True)
class DecisionTrace:
    decision: str
    reason_chain: list[str]
    capability_result: str
    policy_result: str
    final_decision: str
    capability_reason: str | None = None
    capability_metadata: dict[str, CapabilityDefinition] | None = None
    policy_reason: str | None = None
    policy_decision: PolicyDecision | None = None


@dataclass(slots=True)
class DryRunResult:
    would_allow: bool
    would_block: bool
    would_require_approval: bool
    reason: str


class DryRunResultModel(BaseModel):
    would_allow: bool
    would_block: bool
    would_require_approval: bool
    reason: str


class ExplainTraceModel(BaseModel):
    reason_chain: list[str]
    capability_result: str
    policy_result: str
    final_decision: str
    capability_metadata: dict[str, dict[str, Any]] | None = None


class APIResponse(BaseModel):
    status: str
    decision: str
    reason: str
    data: dict[str, Any] | None = None
    trace: ExplainTraceModel | None = None


class ReplayTimelineEntryModel(BaseModel):
    timestamp: str
    event_type: str
    schema_version: str | None = None
    event_id: str | None = None
    decision_stage: str | None = None
    agent_name: str | None = None
    tool_name: str | None = None
    decision: str
    reason: str | None = None
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    execution_plan_id: str | None = None
    plan_id: str | None = None
    plan_intent: str | None = None
    plan_risk_level: str | None = None
    requested_capabilities: list[str] = Field(default_factory=list)
    plan_steps: list[dict[str, Any]] = Field(default_factory=list)
    model_output: str | None = None
    user_input: str | None = None


class ReplayTraceResponseModel(BaseModel):
    trace_id: str
    event_count: int
    execution_plan_ids: list[str] = Field(default_factory=list)
    timeline: list[ReplayTimelineEntryModel] = Field(default_factory=list)
    schema_versions_observed: list[str] = Field(default_factory=list)
    provenance_summary: dict[str, int] = Field(default_factory=dict)
    final_decision: str | None = None
    final_reason: str | None = None
    plan_id: str | None = None
    intent: str | None = None
    risk_level: str | None = None
    requested_capabilities: list[str] | None = None
    step_count: int | None = None


class ReplaySummaryResponseModel(BaseModel):
    trace_id: str
    event_count: int
    final_decision: str | None = None
    tool_name: str | None = None
    final_reason: str | None = None
    provenance_trust_summary: dict[str, int] = Field(default_factory=dict)
    schema_versions_observed: list[str] = Field(default_factory=list)
    plan_id: str | None = None
    intent: str | None = None
    risk_level: str | None = None
    requested_capabilities: list[str] | None = None
    step_count: int | None = None


@dataclass(slots=True)
class ApprovalRequest:
    approval_id: str
    agent_name: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    status: str = "pending"
    risk_level: str = "high"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    review_note: str | None = None
