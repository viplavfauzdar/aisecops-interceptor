from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.models import ToolCall
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.policy.loader import PolicyLoader
from aisecops_interceptor.policy.schema import PolicyBundleValidationError


def test_policy_loader_loads_valid_yaml(tmp_path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "\n".join(
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
        ),
        encoding="utf-8",
    )

    bundle = PolicyLoader.from_yaml(str(policy_file))

    assert len(bundle.rules) == 2
    assert bundle.rules[0].tool_name == "restart_service"
    assert bundle.rules[0].action == "require_approval"
    assert bundle.rules[1].sensitivity_level == "high"


def test_policy_loader_rejects_invalid_yaml(tmp_path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "rules:",
                "  - agent_name: ops_agent",
                "    action: nope",
            ]
        ),
        encoding="utf-8",
    )

    try:
        PolicyLoader.from_yaml(str(policy_file))
        assert False, "Expected PolicyBundleValidationError"
    except PolicyBundleValidationError as exc:
        assert "tool_name" in str(exc) or "action" in str(exc)


def test_policy_engine_from_yaml_executes_loaded_rules(tmp_path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "rules:",
                "  - tool_name: read_customer",
                "    sensitivity_level: high",
                "    action: block",
            ]
        ),
        encoding="utf-8",
    )

    engine = PolicyEngine.from_yaml(str(policy_file))
    decision = engine.evaluate(
        agent_name="sales_agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
        context=RuntimeContext(
            agent_name="sales_agent",
            tool_name="read_customer",
            sensitivity_level="high",
        ),
    )

    assert decision.allowed is False
    assert decision.matched_rule == "rules[0]"
