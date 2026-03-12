from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import AuditEvent
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.models import InterceptionRequest, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.core.decision import DecisionResult, DecisionType
from aisecops_interceptor.core.execution import ExecutionGate


class AgentInterceptor:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.approval_store = approval_store or ApprovalStore()
        self.execution_gate = ExecutionGate()

    def intercept(self, request: InterceptionRequest) -> Any:
        context = request.context
        tool_call = context.to_tool_call()
        decision = self.evaluate(agent_name=context.agent_name, tool_call=tool_call, context=context)

        if decision.requires_approval and not self.approval_store.is_approved(request.approval_id):
            approval_request = self.approval_store.create_request(
                agent_name=context.agent_name,
                tool_call=tool_call,
                reason=decision.reason,
                risk_level=decision.risk_level,
            )
            self.audit_logger.log(
                AuditEvent.create(
                    agent_name=context.agent_name,
                    tool_name=context.tool_name,
                    framework=context.framework,
                    actor=context.actor,
                    environment=context.environment,
                    session_id=context.session_id,
                    correlation_id=context.correlation_id,
                    allowed=False,
                    reason=decision.reason,
                    arguments=context.arguments,
                    risk_level=decision.risk_level,
                    matched_rule=decision.matched_rule,
                    approval_id=approval_request.approval_id,
                )
            )
            raise ApprovalRequiredError(decision.reason, approval_id=approval_request.approval_id)

        approved = self.approval_store.is_approved(request.approval_id)
        self.audit_logger.log(
            AuditEvent.create(
                agent_name=context.agent_name,
                tool_name=context.tool_name,
                framework=context.framework,
                actor=context.actor,
                environment=context.environment,
                session_id=context.session_id,
                correlation_id=context.correlation_id,
                allowed=decision.allowed or approved,
                reason=(f"{decision.reason} (approved)" if approved and decision.requires_approval else decision.reason),
                arguments=context.arguments,
                risk_level=decision.risk_level,
                matched_rule=decision.matched_rule,
                approval_id=request.approval_id,
            )
        )

        if not decision.allowed and not (decision.requires_approval and approved):
            raise PolicyViolationError(decision.reason)

        tool = request.tool_registry.get(context.tool_name)
        if tool is None:
            raise ToolNotFoundError(f"Tool '{context.tool_name}' not found")

        decision_result = DecisionResult(
            decision=(
                DecisionType.ALLOW
                if (decision.allowed or approved)
                else DecisionType.BLOCK
            ),
            reason=decision.reason,
        )

        return self.execution_gate.execute(
            decision_result,
            tool,
            **context.arguments,
        )

    def evaluate(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None = None,
    ):
        return self.policy_engine.evaluate(agent_name=agent_name, tool_call=tool_call, context=context)

    def execute(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        tool_registry: dict[str, Callable[..., Any]],
        approval_id: str | None = None,
    ) -> Any:
        context = RuntimeContext(
            agent_name=agent_name,
            tool_name=tool_call.name,
            arguments=tool_call.arguments,
            framework="legacy",
        )
        return self.intercept(
            InterceptionRequest(
                context=context,
                tool_registry=tool_registry,
                approval_id=approval_id,
            )
        )
