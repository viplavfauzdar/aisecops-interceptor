from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from aisecops_interceptor.core.context import RuntimeContext


@dataclass(slots=True)
class AuditEvent:
    timestamp: str
    agent_name: str
    tool_name: str
    allowed: bool
    reason: str
    arguments: dict[str, object]
    framework: str = "custom"
    actor: str | None = None
    environment: str = "dev"
    session_id: str | None = None
    correlation_id: str | None = None
    risk_level: str = "low"
    matched_rule: str | None = None
    approval_id: str | None = None

    @classmethod
    def create(
        cls,
        *,
        agent_name: str,
        tool_name: str,
        framework: str = "custom",
        actor: str | None = None,
        environment: str = "dev",
        session_id: str | None = None,
        correlation_id: str | None = None,
        allowed: bool,
        reason: str,
        arguments: dict[str, object],
        risk_level: str = "low",
        matched_rule: str | None = None,
        approval_id: str | None = None,
    ) -> "AuditEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_name=agent_name,
            tool_name=tool_name,
            framework=framework,
            actor=actor,
            environment=environment,
            session_id=session_id,
            correlation_id=correlation_id,
            allowed=allowed,
            reason=reason,
            arguments=arguments,
            risk_level=risk_level,
            matched_rule=matched_rule,
            approval_id=approval_id,
        )


@dataclass(slots=True)
class LLMSecurityEvent:
    timestamp: datetime
    event_type: str
    decision: str
    reason: str | None = None
    stage: str | None = None
    context: RuntimeContext | None = None
