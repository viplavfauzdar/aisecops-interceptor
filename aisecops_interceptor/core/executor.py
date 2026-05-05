from __future__ import annotations

from typing import Any

from aisecops_interceptor.core.decision import DecisionResult, DecisionType
from aisecops_interceptor.core.execution import ExecutionGate
from aisecops_interceptor.core.exceptions import PolicyViolationError, ToolNotFoundError
from aisecops_interceptor.core.models import ExecutionPlan


class PlanExecutor:
    def __init__(self, execution_gate: ExecutionGate | None = None) -> None:
        self.execution_gate = execution_gate or ExecutionGate()

    def run(self, plan: ExecutionPlan) -> Any:
        trace = plan.trace
        if trace is None or trace.policy_decision is None:
            raise RuntimeError("Execution plan must be evaluated before execution")

        if trace.final_decision == "blocked":
            raise PolicyViolationError(trace.capability_reason or trace.policy_reason or "Execution blocked")

        tool = plan.tool_registry.get(plan.context.tool_name)
        if tool is None:
            raise ToolNotFoundError(f"Tool '{plan.context.tool_name}' not found")

        decision_result = DecisionResult(
            decision=DecisionType.ALLOW,
            reason=trace.policy_reason,
        )
        return self.execution_gate.execute(
            decision_result,
            tool,
            **plan.context.arguments,
        )
