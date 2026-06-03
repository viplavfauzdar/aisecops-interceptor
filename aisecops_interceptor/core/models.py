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
class RuntimeBudget:
    max_tool_calls: int = 20
    max_depth: int = 5
    max_runtime_seconds: float = 60
    max_cost_usd: float = 2.00

    def to_dict(self) -> dict[str, int | float]:
        return {
            "max_tool_calls": self.max_tool_calls,
            "max_depth": self.max_depth,
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_cost_usd": self.max_cost_usd,
        }


@dataclass(slots=True)
class RuntimeUsage:
    tool_calls_used: int = 0
    depth_used: int = 0
    runtime_seconds: float = 0
    estimated_cost_usd: float = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "tool_calls_used": self.tool_calls_used,
            "depth_used": self.depth_used,
            "runtime_seconds": self.runtime_seconds,
            "estimated_cost_usd": self.estimated_cost_usd,
        }


@dataclass(slots=True)
class AgentIdentity:
    agent_id: str
    agent_name: str
    trust_level: str = "unspecified"
    environment: str = "dev"
    allowed_capabilities: list[str] = field(default_factory=list)
    max_tool_calls: int | None = None
    max_depth: int | None = None
    max_runtime_seconds: float | None = None
    max_cost_usd: float | None = None

    def runtime_budget_overrides(self) -> dict[str, int | float]:
        values: dict[str, int | float] = {}
        if self.max_tool_calls is not None:
            values["max_tool_calls"] = self.max_tool_calls
        if self.max_depth is not None:
            values["max_depth"] = self.max_depth
        if self.max_runtime_seconds is not None:
            values["max_runtime_seconds"] = self.max_runtime_seconds
        if self.max_cost_usd is not None:
            values["max_cost_usd"] = self.max_cost_usd
        return values

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "trust_level": self.trust_level,
            "environment": self.environment,
            "allowed_capabilities": list(self.allowed_capabilities),
            **self.runtime_budget_overrides(),
        }


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
    agent_id: str | None = None
    agent_trust_level: str | None = None
    agent_environment: str | None = None
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
    protocol: str | None = None
    client_id: str | None = None
    server_name: str | None = None
    capability: str | None = None
    budget_status: str | None = None
    runtime_budget: dict[str, Any] | None = None
    runtime_usage: dict[str, Any] | None = None
    runtime_violations: list[str] | None = None
    tool_calls_used: int | None = None
    tool_calls_remaining: int | None = None
    depth_used: int | None = None
    runtime_seconds: float | None = None
    estimated_cost_usd: float | None = None


class ReplayTraceResponseModel(BaseModel):
    trace_id: str
    event_count: int
    execution_plan_ids: list[str] = Field(default_factory=list)
    timeline: list[ReplayTimelineEntryModel] = Field(default_factory=list)
    schema_versions_observed: list[str] = Field(default_factory=list)
    provenance_summary: dict[str, int] = Field(default_factory=dict)
    final_decision: str | None = None
    final_reason: str | None = None
    agent_id: str | None = None
    agent_trust_level: str | None = None
    agent_environment: str | None = None
    plan_id: str | None = None
    intent: str | None = None
    risk_level: str | None = None
    requested_capabilities: list[str] | None = None
    step_count: int | None = None
    protocol: str | None = None
    client_id: str | None = None
    server_name: str | None = None
    capability: str | None = None
    budget_status: str | None = None
    usage_summary: dict[str, Any] | None = None
    violations: list[str] | None = None


class ReplaySummaryResponseModel(BaseModel):
    trace_id: str
    event_count: int
    final_decision: str | None = None
    tool_name: str | None = None
    final_reason: str | None = None
    provenance_trust_summary: dict[str, int] = Field(default_factory=dict)
    schema_versions_observed: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_trust_level: str | None = None
    agent_environment: str | None = None
    plan_id: str | None = None
    intent: str | None = None
    risk_level: str | None = None
    requested_capabilities: list[str] | None = None
    step_count: int | None = None
    protocol: str | None = None
    client_id: str | None = None
    server_name: str | None = None
    capability: str | None = None
    budget_status: str | None = None
    usage_summary: dict[str, Any] | None = None
    violations: list[str] | None = None


class ReplayMismatchModel(BaseModel):
    type: str
    expected: str | None = None
    actual: str | None = None
    severity: str
    reason: str


class ReplayDiffResponseModel(BaseModel):
    trace_id: str
    plan_id: str | None = None
    planned_tool: str | None = None
    planned_intent: str | None = None
    planned_capabilities: list[str] = Field(default_factory=list)
    planned_risk_level: str | None = None
    policy_decision: str | None = None
    execution_outcome: str | None = None
    governance_result: str
    mismatches: list[ReplayMismatchModel] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)
    summary: str


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
