from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    matched_rule: str | None = None
    risk_level: str = "low"
    requires_approval: bool = False


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


@dataclass(slots=True)
class AuditEvent:
    timestamp: str
    agent_name: str
    tool_name: str
    allowed: bool
    reason: str
    arguments: dict[str, Any]
    risk_level: str = "low"
    matched_rule: str | None = None
    approval_id: str | None = None

    @classmethod
    def create(
        cls,
        *,
        agent_name: str,
        tool_name: str,
        allowed: bool,
        reason: str,
        arguments: dict[str, Any],
        risk_level: str = "low",
        matched_rule: str | None = None,
        approval_id: str | None = None,
    ) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_name=agent_name,
            tool_name=tool_name,
            allowed=allowed,
            reason=reason,
            arguments=arguments,
            risk_level=risk_level,
            matched_rule=matched_rule,
            approval_id=approval_id,
        )
