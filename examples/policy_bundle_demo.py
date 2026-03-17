from __future__ import annotations

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.models import ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


def main() -> None:
    engine = PolicyEngine.from_yaml("policies/policies.yaml")

    approval_decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "payments"}),
        context=RuntimeContext(agent_name="ops_agent", tool_name="restart_service"),
    )
    print(
        {
            "tool": "restart_service",
            "allowed": approval_decision.allowed,
            "requires_approval": approval_decision.requires_approval,
            "reason": approval_decision.reason,
        }
    )

    blocked_decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="shell_exec", arguments={"command": "rm -rf /tmp/demo"}),
        context=RuntimeContext(
            agent_name="ops_agent",
            tool_name="shell_exec",
        ),
    )
    print(
        {
            "tool": "shell_exec",
            "allowed": blocked_decision.allowed,
            "requires_approval": blocked_decision.requires_approval,
            "reason": blocked_decision.reason,
        }
    )


if __name__ == "__main__":
    main()
