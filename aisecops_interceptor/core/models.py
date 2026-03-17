from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import BaseModel

from aisecops_interceptor.core.context import RuntimeContext


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


class ExecuteAllowedResponse(BaseModel):
    status: str
    result: dict[str, Any]


class ExecuteDryRunResponse(BaseModel):
    status: str
    result: DryRunResultModel


class ApprovalRequiredResponse(BaseModel):
    status: str
    decision: str
    reason: str
    approval_id: str


class BlockedResponse(BaseModel):
    status: str
    decision: str
    reason: str


class ToolNotFoundResponse(BaseModel):
    status: str
    decision: str
    reason: str


class ExplainResponse(BaseModel):
    decision: str
    reason_chain: list[str]
    capability_result: str
    policy_result: str
    final_decision: str
    capability_metadata: dict[str, dict[str, Any]] | None = None


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
