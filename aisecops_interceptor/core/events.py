from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from aisecops_interceptor.core.context import RuntimeContext


def _sanitize_payload(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _sanitize_payload(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_payload(item) for item in value]
    return str(value)


@dataclass(slots=True)
class RuntimeEvent:
    timestamp: str
    event_type: str
    decision: str
    schema_version: str = "1.0"
    trace_id: str | None = None
    audit_kind: str | None = None
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
    capabilities: list[str] | None = None
    capability_risks: dict[str, str | None] | None = None
    payload: dict[str, Any] | None = None

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
                schema_version=str(data.get("schema_version") or "1.0"),
                trace_id=str(data["trace_id"]) if data.get("trace_id") is not None else None,
                audit_kind=str(data["audit_kind"]) if data.get("audit_kind") is not None else None,
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
                capabilities=list(data["capabilities"]) if isinstance(data.get("capabilities"), list) else None,
                capability_risks=(
                    {str(key): (str(value) if value is not None else None) for key, value in data["capability_risks"].items()}
                    if isinstance(data.get("capability_risks"), dict)
                    else None
                ),
                payload=dict(data["payload"]) if isinstance(data.get("payload"), dict) else None,
            )

        return cls(
            timestamp=str(data["timestamp"]),
            event_type=str(data["event_type"]),
            decision=str(data["decision"]),
            schema_version=str(data.get("schema_version") or "1.0"),
            trace_id=str(data["trace_id"]) if data.get("trace_id") is not None else None,
            audit_kind=str(data["audit_kind"]) if data.get("audit_kind") is not None else None,
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
            capabilities=list(data["capabilities"]) if isinstance(data.get("capabilities"), list) else None,
            capability_risks=(
                {str(key): (str(value) if value is not None else None) for key, value in data["capability_risks"].items()}
                if isinstance(data.get("capability_risks"), dict)
                else None
            ),
            payload=dict(data["payload"]) if isinstance(data.get("payload"), dict) else None,
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
        trace_id: str | None = None,
        correlation_id: str | None = None,
        allowed: bool | None = None,
        reason: str | None = None,
        arguments: dict[str, object] | None = None,
        risk_level: str = "low",
        matched_rule: str | None = None,
        approval_id: str | None = None,
        stage: str | None = None,
        context: RuntimeContext | None = None,
        audit_kind: str | None = None,
        capabilities: list[str] | None = None,
        capability_risks: dict[str, str | None] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> "RuntimeEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            decision=decision,
            trace_id=trace_id,
            audit_kind=audit_kind,
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
            capabilities=capabilities,
            capability_risks=capability_risks,
            payload=_sanitize_payload(payload) if payload is not None else None,
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
        audit_kind: str | None = None,
        capability_risks: dict[str, str | None] | None = None,
        payload: dict[str, Any] | None = None,
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
            trace_id=context.trace_id,
            correlation_id=context.correlation_id,
            allowed=allowed,
            reason=reason,
            arguments=context.arguments,
            risk_level=risk_level,
            matched_rule=matched_rule,
            approval_id=approval_id,
            audit_kind=audit_kind,
            capabilities=list(context.allowed_capabilities) if context.allowed_capabilities is not None else None,
            capability_risks=capability_risks,
            payload=payload,
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
        trace_id: str | None = None,
        audit_kind: str | None = None,
        payload: dict[str, Any] | None = None,
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
            trace_id=context.trace_id if context else trace_id,
            correlation_id=context.correlation_id if context else None,
            allowed=((decision == "allowed") if decision in {"allowed", "blocked"} else None),
            reason=reason,
            arguments=context.arguments if context else None,
            audit_kind=audit_kind,
            capabilities=list(context.allowed_capabilities) if context and context.allowed_capabilities is not None else None,
            payload=payload,
        )

    @classmethod
    def audit_event(
        cls,
        *,
        event_type: str,
        decision: str,
        reason: str | None = None,
        stage: str | None = None,
        context: RuntimeContext | None = None,
        trace_id: str | None = None,
        risk_level: str = "low",
        matched_rule: str | None = None,
        approval_id: str | None = None,
        capabilities: list[str] | None = None,
        capability_risks: dict[str, str | None] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> "RuntimeEvent":
        return cls.create(
            event_type=event_type,
            decision=decision,
            reason=reason,
            stage=stage,
            context=context,
            agent_name=context.agent_name if context else "",
            tool_name=context.tool_name if context else None,
            framework=context.framework if context else "custom",
            actor=context.actor if context else None,
            environment=context.environment if context else "dev",
            session_id=context.session_id if context else None,
            trace_id=context.trace_id if context else trace_id,
            correlation_id=context.correlation_id if context else None,
            allowed=None,
            arguments=context.arguments if context else None,
            risk_level=risk_level,
            matched_rule=matched_rule,
            approval_id=approval_id,
            audit_kind=event_type,
            capabilities=(
                capabilities
                if capabilities is not None
                else (list(context.allowed_capabilities) if context and context.allowed_capabilities is not None else None)
            ),
            capability_risks=capability_risks,
            payload=payload,
        )
