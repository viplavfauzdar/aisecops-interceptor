from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

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
class DecisionTrace:
    decision: str
    reason_chain: list[str]
    capability_result: str
    policy_result: str
    final_decision: str
    capability_reason: str | None = None
    policy_reason: str | None = None
    policy_decision: PolicyDecision | None = None


@dataclass(slots=True)
class DryRunResult:
    would_allow: bool
    would_block: bool
    would_require_approval: bool
    reason: str


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
