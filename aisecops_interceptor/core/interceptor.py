from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.executor import PlanExecutor
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.models import DecisionTrace, DryRunResult, ExecutionPlan, InterceptionRequest, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


class AgentInterceptor:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        approval_store: ApprovalStore | None = None,
        capability_registry: CapabilityRegistry | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.approval_store = approval_store or ApprovalStore()
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.executor = PlanExecutor()

    def intercept(self, request: InterceptionRequest) -> Any:
        plan = self.plan(request)
        self.evaluate(plan)
        return self.execute_plan(plan)

    def execute_plan(self, plan: ExecutionPlan) -> Any:
        context = plan.context
        tool_call = context.to_tool_call()
        trace = plan.trace or self.evaluate(plan)
        if trace.capability_result == "blocked":
            self.audit_logger.log(
                RuntimeEvent.tool_event(
                    event_type="tool_blocked",
                    decision="blocked",
                    context=context,
                    allowed=False,
                    reason=trace.capability_reason,
                    risk_level="medium",
                    matched_rule="capability_gate",
                    approval_id=plan.approval_id,
                )
            )
            if plan.dry_run:
                return DryRunResult(
                    would_allow=False,
                    would_block=True,
                    would_require_approval=False,
                    reason=trace.capability_reason or "Capability gate blocked the request",
                )
            raise PolicyViolationError(trace.capability_reason or "Capability gate blocked the request")

        decision = trace.policy_decision
        if decision is None:
            raise PolicyViolationError("Policy evaluation did not return a decision")

        if decision.requires_approval and not self.approval_store.is_approved(plan.approval_id):
            approval_request = self.approval_store.create_request(
                agent_name=context.agent_name,
                tool_call=tool_call,
                reason=decision.reason,
                risk_level=decision.risk_level,
            )
            self.audit_logger.log(
                RuntimeEvent.tool_event(
                    event_type="approval_required",
                    decision="require_approval",
                    context=context,
                    allowed=False,
                    reason=decision.reason,
                    risk_level=decision.risk_level,
                    matched_rule=decision.matched_rule,
                    approval_id=approval_request.approval_id,
                )
            )
            if plan.dry_run:
                return DryRunResult(
                    would_allow=False,
                    would_block=False,
                    would_require_approval=True,
                    reason=decision.reason,
                )
            raise ApprovalRequiredError(decision.reason, approval_id=approval_request.approval_id)

        approved = self.approval_store.is_approved(plan.approval_id)
        self.audit_logger.log(
            RuntimeEvent.tool_event(
                event_type="tool_allowed" if (decision.allowed or approved) else "tool_blocked",
                decision="allowed" if (decision.allowed or approved) else "blocked",
                context=context,
                allowed=decision.allowed or approved,
                reason=(f"{decision.reason} (approved)" if approved and decision.requires_approval else decision.reason),
                risk_level=decision.risk_level,
                matched_rule=decision.matched_rule,
                approval_id=plan.approval_id,
            )
        )

        if not decision.allowed and not (decision.requires_approval and approved):
            if plan.dry_run:
                return DryRunResult(
                    would_allow=False,
                    would_block=True,
                    would_require_approval=False,
                    reason=decision.reason,
                )
            raise PolicyViolationError(decision.reason)

        if plan.dry_run:
            return DryRunResult(
                would_allow=True,
                would_block=False,
                would_require_approval=False,
                reason=(f"{decision.reason} (approved)" if approved and decision.requires_approval else decision.reason),
            )

        result = self.executor.run(plan)
        self.audit_logger.log(
            RuntimeEvent.tool_event(
                event_type="tool_executed",
                decision="allowed",
                context=context,
                allowed=True,
                reason="Tool executed",
                risk_level=decision.risk_level,
                matched_rule=decision.matched_rule,
                approval_id=plan.approval_id,
            )
        )
        return result

    def explain(self, request: InterceptionRequest) -> DecisionTrace:
        return self.evaluate(self.plan(request))

    def plan(self, request: InterceptionRequest) -> ExecutionPlan:
        return ExecutionPlan(
            context=request.context,
            tool_registry=request.tool_registry,
            approval_id=request.approval_id,
            dry_run=request.dry_run,
        )

    def evaluate(self, plan: ExecutionPlan) -> DecisionTrace:
        context = plan.context
        tool_call = context.to_tool_call()
        reason_chain: list[str] = []
        capability_metadata = (
            self.capability_registry.metadata_for_tool(context.tool_name)
            if context.tool_name is not None
            else None
        ) or None

        capability_reason = self._capability_denial_reason(context)
        if capability_reason is not None:
            reason_chain.append(capability_reason)
            trace = DecisionTrace(
                decision="blocked",
                reason_chain=reason_chain,
                capability_result="blocked",
                policy_result="not_evaluated",
                final_decision="blocked",
                capability_reason=capability_reason,
                capability_metadata=capability_metadata,
            )
            plan.trace = trace
            return trace

        capability_result = "not_applicable" if context.allowed_capabilities is None else "allowed"
        if capability_result == "not_applicable":
            reason_chain.append("Capability gate skipped because no capabilities were provided")
            reason_chain.extend(
                self._capability_context_reasons(
                    tool_name=context.tool_name,
                    capability_result=capability_result,
                )
            )
        else:
            capability_reasons = self._capability_context_reasons(
                tool_name=context.tool_name,
                capability_result=capability_result,
            )
            if capability_reasons:
                reason_chain.extend(capability_reasons)
            else:
                reason_chain.append(
                    f"Capability gate allowed tool '{context.tool_name}' for the granted capabilities"
                )

        decision = self._evaluate_policy(agent_name=context.agent_name, tool_call=tool_call, context=context)
        policy_result = "require_approval" if decision.requires_approval else ("allowed" if decision.allowed else "blocked")
        reason_chain.append(decision.reason)
        trace = DecisionTrace(
            decision=policy_result,
            reason_chain=reason_chain,
            capability_result=capability_result,
            policy_result=policy_result,
            final_decision=policy_result,
            capability_metadata=capability_metadata,
            policy_reason=decision.reason,
            policy_decision=decision,
        )
        plan.trace = trace
        return trace

    def _evaluate_policy(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None = None,
    ):
        return self.policy_engine.evaluate(agent_name=agent_name, tool_call=tool_call, context=context)

    def _capability_denial_reason(self, context: RuntimeContext) -> str | None:
        if context.allowed_capabilities is None or context.tool_name is None:
            return None
        if self.capability_registry.is_tool_allowed(context.tool_name, context.allowed_capabilities):
            return None

        required_capabilities = self.capability_registry.required_capabilities_for_tool(context.tool_name)
        if required_capabilities:
            capability_list = ", ".join(required_capabilities)
            return (
                f"Tool '{context.tool_name}' requires one of the granted capabilities: {capability_list}"
            )
        return f"Tool '{context.tool_name}' is not granted by the provided capabilities"

    def _capability_context_reasons(self, *, tool_name: str | None, capability_result: str) -> list[str]:
        if tool_name is None:
            return []

        reasons: list[str] = []
        for capability_name, definition in self.capability_registry.metadata_for_tool(tool_name).items():
            risk_suffix = f" (risk: {definition.risk})" if definition.risk is not None else ""
            if capability_result == "allowed":
                reasons.append(
                    f"Capability {capability_name}{risk_suffix} allowed access to {tool_name}"
                )
            else:
                reasons.append(
                    f"Capability {capability_name}{risk_suffix} governs access to {tool_name}"
                )
        return reasons

    def execute(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        tool_registry: dict[str, Callable[..., Any]],
        approval_id: str | None = None,
        dry_run: bool = False,
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
                dry_run=dry_run,
            )
        )
