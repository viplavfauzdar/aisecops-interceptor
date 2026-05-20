from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.planning.capabilities import requested_capabilities_for_tool
from aisecops_interceptor.planning.extractor import extract_plan
from aisecops_interceptor.planning.models import ExecutionPlan, PlanStep
from aisecops_interceptor.planning.risk import score_plan


def test_extracts_plan_from_explicit_tool_request() -> None:
    context = RuntimeContext(
        agent_name="ops_agent",
        prompt="Restart the payments API",
        tool_name="restart_service",
        arguments={"service": "payments-api"},
        allowed_capabilities=["infra.restart"],
        trace_id="trace-1",
    )

    plan = extract_plan(context, plan_id="plan-1")

    assert plan.schema_version == "0.8.0"
    assert plan.plan_id == "plan-1"
    assert plan.trace_id == "trace-1"
    assert plan.intent == "restart_service"
    assert plan.requested_tool == "restart_service"
    assert plan.requested_capabilities == ["infra.restart"]
    assert plan.targets == ["payments-api"]
    assert plan.parameters == {"service": "payments-api"}
    assert plan.risk_level == "critical"
    assert plan.steps[0].tool_name == "restart_service"
    assert plan.steps[0].capability == "infra.restart"


def test_extracts_plan_from_model_text_without_external_llm() -> None:
    context = RuntimeContext(
        agent_name="ops_agent",
        prompt="Please handle the incident",
        model_output=(
            '{"intent":"restart_service","requested_tool":"restart_service",'
            '"requested_capabilities":["infra.restart"],"targets":["payments-api"],'
            '"parameters":{"service":"payments-api"}}'
        ),
        trace_id="trace-2",
    )

    plan = extract_plan(context, plan_id="plan-2")

    assert plan.intent == "restart_service"
    assert plan.requested_tool == "restart_service"
    assert plan.requested_capabilities == ["infra.restart"]
    assert plan.targets == ["payments-api"]
    assert plan.parameters == {"service": "payments-api"}
    assert plan.risk_level == "critical"
    assert plan.steps[0].capability == "infra.restart"


def test_extracts_canonical_capabilities_for_known_tools() -> None:
    cases = {
        "restart_service": "infra.restart",
        "read_customer": "customer.read",
        "send_email": "email.send",
    }

    for tool_name, capability in cases.items():
        plan = extract_plan(
            RuntimeContext(
                agent_name="demo_agent",
                tool_name=tool_name,
                arguments={},
            )
        )

        assert plan.requested_capabilities == [capability]
        assert plan.steps[0].capability == capability


def test_unknown_tool_uses_safe_capability_fallback() -> None:
    assert requested_capabilities_for_tool("custom_tool") == ["custom.tool"]


def test_score_plan_maps_initial_risk_categories() -> None:
    cases = {
        "read_customer": "low",
        "write_record": "high",
        "delete_record": "high",
        "shell_exec": "critical",
        "restart_service": "critical",
    }

    for tool_name, risk_level in cases.items():
        plan = ExecutionPlan(
            intent=tool_name,
            requested_tool=tool_name,
            steps=[PlanStep(intent=tool_name, tool_name=tool_name)],
        )

        assert score_plan(plan) == risk_level


def test_score_plan_marks_infra_restart_capability_critical() -> None:
    plan = ExecutionPlan(
        intent="restart_service",
        requested_tool="unknown_tool",
        requested_capabilities=["infra.restart"],
        steps=[
            PlanStep(
                intent="restart_service",
                tool_name="unknown_tool",
                capability="infra.restart",
            )
        ],
    )

    assert score_plan(plan) == "critical"
