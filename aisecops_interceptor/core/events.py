from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuntimeEvent":
        context_data = data.get("context")
        context = RuntimeContext(**context_data) if isinstance(context_data, dict) else None
        if "event_type" not in data:
            is_allowed = bool(data["allowed"]) if data.get("allowed") is not None else None
            reason = str(data["reason"]) if data.get("reason") is not None else None
            if is_allowed:
                event_type = "tool_allowed"
                decision = "allowed"
            elif data.get("approval_id") is not None and reason and "approval" in reason.lower():
                event_type = "approval_required"
                decision = "require_approval"
            else:
                event_type = "tool_blocked"
                decision = "blocked"

            return cls(
                timestamp=str(data["timestamp"]),
                event_type=event_type,
                decision=decision,
                reason=reason,
                stage="tool",
                context=context,
                agent_name=str(data["agent_name"]) if data.get("agent_name") is not None else None,
                tool_name=str(data["tool_name"]) if data.get("tool_name") is not None else None,
                allowed=is_allowed,
                arguments=dict(data["arguments"]) if isinstance(data.get("arguments"), dict) else None,
                framework=str(data.get("framework") or "custom"),
                actor=str(data["actor"]) if data.get("actor") is not None else None,
                environment=str(data.get("environment") or "dev"),
                session_id=str(data["session_id"]) if data.get("session_id") is not None else None,
                correlation_id=(
                    str(data["correlation_id"]) if data.get("correlation_id") is not None else None
                ),
                risk_level=str(data.get("risk_level") or "low"),
                matched_rule=str(data["matched_rule"]) if data.get("matched_rule") is not None else None,
                approval_id=str(data["approval_id"]) if data.get("approval_id") is not None else None,
            )

        return cls(
            timestamp=str(data["timestamp"]),
            event_type=str(data["event_type"]),
            decision=str(data["decision"]),
            reason=str(data["reason"]) if data.get("reason") is not None else None,
            stage=str(data["stage"]) if data.get("stage") is not None else None,
            context=context,
            agent_name=str(data["agent_name"]) if data.get("agent_name") is not None else None,
            tool_name=str(data["tool_name"]) if data.get("tool_name") is not None else None,
            allowed=bool(data["allowed"]) if data.get("allowed") is not None else None,
            arguments=dict(data["arguments"]) if isinstance(data.get("arguments"), dict) else None,
            framework=str(data.get("framework") or "custom"),
            actor=str(data["actor"]) if data.get("actor") is not None else None,
            environment=str(data.get("environment") or "dev"),
            session_id=str(data["session_id"]) if data.get("session_id") is not None else None,
            correlation_id=(
                str(data["correlation_id"]) if data.get("correlation_id") is not None else None
            ),
            risk_level=str(data.get("risk_level") or "low"),
            matched_rule=str(data["matched_rule"]) if data.get("matched_rule") is not None else None,
            approval_id=str(data["approval_id"]) if data.get("approval_id") is not None else None,
        )

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
