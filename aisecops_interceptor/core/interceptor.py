from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.models import AuditEvent, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


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

    def evaluate(self, *, agent_name: str, tool_call: ToolCall):
        return self.policy_engine.evaluate(agent_name=agent_name, tool_call=tool_call)

    def execute(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        tool_registry: dict[str, Callable[..., Any]],
        approval_id: str | None = None,
    ) -> Any:
        decision = self.evaluate(agent_name=agent_name, tool_call=tool_call)

        if decision.requires_approval and not self.approval_store.is_approved(approval_id):
            request = self.approval_store.create_request(
                agent_name=agent_name,
                tool_call=tool_call,
                reason=decision.reason,
                risk_level=decision.risk_level,
            )
            self.audit_logger.log(
                AuditEvent.create(
                    agent_name=agent_name,
                    tool_name=tool_call.name,
                    allowed=False,
                    reason=decision.reason,
                    arguments=tool_call.arguments,
                    risk_level=decision.risk_level,
                    matched_rule=decision.matched_rule,
                    approval_id=request.approval_id,
                )
            )
            raise ApprovalRequiredError(decision.reason, approval_id=request.approval_id)

        self.audit_logger.log(
            AuditEvent.create(
                agent_name=agent_name,
                tool_name=tool_call.name,
                allowed=decision.allowed or self.approval_store.is_approved(approval_id),
                reason=(decision.reason if not approval_id else f"{decision.reason} (approved)") if decision.requires_approval else decision.reason,
                arguments=tool_call.arguments,
                risk_level=decision.risk_level,
                matched_rule=decision.matched_rule,
                approval_id=approval_id,
            )
        )

        if not decision.allowed and not (decision.requires_approval and self.approval_store.is_approved(approval_id)):
            raise PolicyViolationError(decision.reason)

        tool = tool_registry.get(tool_call.name)
        if tool is None:
            raise ToolNotFoundError(f"Tool '{tool_call.name}' not found")

        return tool(**tool_call.arguments)
