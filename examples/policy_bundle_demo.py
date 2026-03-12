from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.models import ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


def main() -> None:
    yaml_policy = "\n".join(
        [
            "rules:",
            "  - tool_name: restart_service",
            "    agent_name: ops_agent",
            "    action: require_approval",
            "",
            "  - tool_name: read_customer",
            "    sensitivity_level: high",
            "    action: block",
        ]
    )

    with TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "production.yaml"
        policy_path.write_text(yaml_policy, encoding="utf-8")

        engine = PolicyEngine.from_yaml(str(policy_path))

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
            agent_name="sales_agent",
            tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
            context=RuntimeContext(
                agent_name="sales_agent",
                tool_name="read_customer",
                sensitivity_level="high",
            ),
        )
        print(
            {
                "tool": "read_customer",
                "allowed": blocked_decision.allowed,
                "requires_approval": blocked_decision.requires_approval,
                "reason": blocked_decision.reason,
            }
        )


if __name__ == "__main__":
    main()
