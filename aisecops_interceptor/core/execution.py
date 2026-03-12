from .decision import DecisionType, DecisionResult


class ExecutionGate:

    def execute(self, decision: DecisionResult, tool_callable, *args, **kwargs):

        if decision.decision == DecisionType.BLOCK:
            raise RuntimeError(f"Execution blocked: {decision.reason}")

        if decision.decision == DecisionType.REQUIRE_APPROVAL:
            return {
                "approval_required": True,
                "reason": decision.reason
            }

        return tool_callable(*args, **kwargs)
