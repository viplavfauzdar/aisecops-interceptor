from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.models import InstructionProvenance, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.policy.rules import Rule


def test_rule_engine_allow_rule_overrides_default_policy() -> None:
    engine = PolicyEngine(
        {"blocked_tools": ["restart_service"]},
        rules=[Rule(tool_name="restart_service", agent_name="ops_agent", action="allow")],
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
    )

    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.matched_rule == "rules[0]"


def test_rule_engine_block_rule_works() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name="send_email", agent_name="sales_agent", action="block")],
    )

    decision = engine.evaluate(
        agent_name="sales_agent",
        tool_call=ToolCall(name="send_email", arguments={"to": "test@example.com"}),
    )

    assert decision.allowed is False
    assert decision.requires_approval is False
    assert "blocked" in decision.reason.lower()


def test_rule_engine_approval_rule_works() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name="restart_service", agent_name="ops_agent", action="require_approval")],
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
    assert "approval" in decision.reason.lower()


def test_rule_engine_sensitivity_rule_works() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name="read_customer", sensitivity_level="high", action="block")],
    )

    decision = engine.evaluate(
        agent_name="sales_agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
        context=RuntimeContext(
            agent_name="sales_agent",
            tool_name="read_customer",
            sensitivity_level="high",
            data_classification="pii",
        ),
    )

    assert decision.allowed is False
    assert decision.requires_approval is False
    assert decision.matched_rule == "rules[0]"


def test_default_high_risk_preset_requires_approval() -> None:
    engine = PolicyEngine(
        {
            "agents": {
                "ops_agent": {
                    "allowed_tools": ["export_data"],
                },
            },
        }
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="export_data", arguments={"scope": "customers"}),
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
    assert decision.matched_rule == "high_risk_tools"


def test_default_high_risk_preset_uses_canonical_shell_tool_name() -> None:
    engine = PolicyEngine(
        {
            "agents": {
                "ops_agent": {
                    "allowed_tools": ["shell_exec"],
                },
            },
            "blocked_tools": [],
        }
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="shell_exec", arguments={"command": "echo ok"}),
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
    assert decision.matched_rule == "high_risk_tools"


def test_explicit_rule_overrides_high_risk_preset() -> None:
    engine = PolicyEngine(
        {
            "agents": {
                "ops_agent": {
                    "allowed_tools": ["export_data"],
                },
            },
        },
        rules=[Rule(tool_name="export_data", agent_name="ops_agent", action="allow")],
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="export_data", arguments={"scope": "customers"}),
    )

    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.matched_rule == "rules[0]"


def test_non_preset_safe_tool_remains_allowed() -> None:
    engine = PolicyEngine(
        {
            "agents": {
                "sales_agent": {
                    "allowed_tools": ["read_customer"],
                },
            },
        }
    )

    decision = engine.evaluate(
        agent_name="sales_agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
    )

    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.reason == "Allowed by policy"


def test_rule_engine_blocks_on_provenance_trust() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name="send_email", action="block", provenance_trust=("external", "unverified"))],
    )

    decision = engine.evaluate(
        agent_name="sales_agent",
        tool_call=ToolCall(name="send_email", arguments={"to": "test@example.com"}),
        context=RuntimeContext(
            agent_name="sales_agent",
            tool_name="send_email",
            provenance=[
                InstructionProvenance(source_type="user_prompt", source_name="user", trust_level="external"),
            ],
        ),
    )

    assert decision.allowed is False
    assert decision.requires_approval is False
    assert decision.matched_rule == "rules[0]"


def test_rule_engine_requires_approval_on_provenance_source_type() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name="restart_service", action="require_approval", provenance_source_type=("skill",))],
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
        context=RuntimeContext(
            agent_name="ops_agent",
            tool_name="restart_service",
            provenance=[
                InstructionProvenance(source_type="skill", source_name="helper", trust_level="unverified"),
            ],
        ),
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
    assert decision.matched_rule == "rules[0]"


def test_rule_engine_keeps_existing_behavior_when_provenance_missing() -> None:
    engine = PolicyEngine(
        {
            "agents": {
                "sales_agent": {
                    "allowed_tools": ["send_email"],
                },
            },
        },
        rules=[Rule(tool_name="send_email", action="block", provenance_trust=("external",))],
    )

    decision = engine.evaluate(
        agent_name="sales_agent",
        tool_call=ToolCall(name="send_email", arguments={"to": "test@example.com"}),
        context=RuntimeContext(agent_name="sales_agent", tool_name="send_email"),
    )

    assert decision.allowed is True
    assert decision.reason == "Allowed by policy"


def test_rule_engine_matches_any_provenance_entry() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name="restart_service", action="require_approval", provenance_source_type=("skill",))],
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
        context=RuntimeContext(
            agent_name="ops_agent",
            tool_name="restart_service",
            provenance=[
                InstructionProvenance(source_type="system_prompt", source_name="runbook", trust_level="trusted"),
                InstructionProvenance(source_type="skill", source_name="helper", trust_level="unverified"),
            ],
        ),
    )

    assert decision.allowed is False
    assert decision.requires_approval is True


def test_rule_engine_supports_provenance_only_rule() -> None:
    engine = PolicyEngine(
        {},
        rules=[Rule(tool_name=None, action="require_approval", provenance_source_type=("retrieval_chunk",))],
    )

    decision = engine.evaluate(
        agent_name="ops_agent",
        tool_call=ToolCall(name="create_incident", arguments={"service": "orders"}),
        context=RuntimeContext(
            agent_name="ops_agent",
            tool_name="create_incident",
            provenance=[
                InstructionProvenance(
                    source_type="retrieval_chunk",
                    source_name="kb-doc",
                    trust_level="external",
                ),
            ],
        ),
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
