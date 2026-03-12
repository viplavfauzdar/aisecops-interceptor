from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from aisecops_interceptor.core.context import RuntimeContext


@dataclass(slots=True)
class RuntimeEvent:
    timestamp: str
    event_type: str
    decision: str
    reason: str | None = None
    stage: str | None = None
    context: RuntimeContext | None = None
    agent_name: str | None = None
    tool_name: str | None = None
    allowed: bool | None = None
    arguments: dict[str, object] | None = None
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
        event_type: str,
        decision: str,
        agent_name: str,
        tool_name: str | None = None,
        framework: str = "custom",
        actor: str | None = None,
        environment: str = "dev",
        session_id: str | None = None,
        correlation_id: str | None = None,
        allowed: bool | None = None,
        reason: str | None = None,
        arguments: dict[str, object] | None = None,
        risk_level: str = "low",
        matched_rule: str | None = None,
        approval_id: str | None = None,
        stage: str | None = None,
        context: RuntimeContext | None = None,
    ) -> "RuntimeEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            decision=decision,
            reason=reason,
            stage=stage,
            context=context,
            agent_name=agent_name,
            tool_name=tool_name,
            allowed=allowed,
            arguments=arguments,
            framework=framework,
            actor=actor,
            environment=environment,
            session_id=session_id,
            correlation_id=correlation_id,
            risk_level=risk_level,
            matched_rule=matched_rule,
            approval_id=approval_id,
        )

    @classmethod
    def tool_event(
        cls,
        *,
        event_type: str,
        decision: str,
        context: RuntimeContext,
        allowed: bool | None,
        reason: str | None,
        risk_level: str = "low",
        matched_rule: str | None = None,
        approval_id: str | None = None,
    ) -> "RuntimeEvent":
        return cls.create(
            event_type=event_type,
            decision=decision,
            stage="tool",
            context=context,
            agent_name=context.agent_name,
            tool_name=context.tool_name,
            framework=context.framework,
            actor=context.actor,
            environment=context.environment,
            session_id=context.session_id,
            correlation_id=context.correlation_id,
            allowed=allowed,
            reason=reason,
            arguments=context.arguments,
            risk_level=risk_level,
            matched_rule=matched_rule,
            approval_id=approval_id,
        )

    @classmethod
    def llm_event(
        cls,
        *,
        event_type: str,
        decision: str,
        reason: str | None = None,
        stage: str | None = None,
        context: RuntimeContext | None = None,
    ) -> "RuntimeEvent":
        return cls.create(
            event_type=event_type,
            decision=decision,
            stage=stage,
            context=context,
            agent_name=context.agent_name if context else None,
            tool_name=context.tool_name if context else None,
            framework=context.framework if context else "custom",
            actor=context.actor if context else None,
            environment=context.environment if context else "dev",
            session_id=context.session_id if context else None,
            correlation_id=context.correlation_id if context else None,
            allowed=(decision == "allowed"),
            reason=reason,
            arguments=context.arguments if context else None,
        )
