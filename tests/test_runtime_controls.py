import json

import pytest

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.exceptions import PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest, RuntimeUsage, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.replay.engine import AuditReplayEngine


def _policy(config: dict | None = None) -> PolicyEngine:
    return PolicyEngine(
        {
            "agent_limits": {
                "max_tool_calls": 2,
                "max_depth": 3,
                "max_runtime_seconds": 10,
                "max_cost_usd": 0.20,
            },
            **(config or {}),
        }
    )


def _decision_for_usage(usage: RuntimeUsage, config: dict | None = None):
    engine = _policy(config)
    return engine.evaluate(
        agent_name="ops-agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
        context=RuntimeContext(
            agent_name="ops-agent",
            tool_name="read_customer",
            runtime_usage=usage,
        ),
    )


def test_tool_call_limit_exceeded() -> None:
    decision = _decision_for_usage(RuntimeUsage(tool_calls_used=2))

    assert decision.allowed is False
    assert decision.reason == "tool_call_budget_exceeded"
    assert decision.matched_rule == "agent_limits"


def test_depth_limit_exceeded() -> None:
    decision = _decision_for_usage(RuntimeUsage(depth_used=3))

    assert decision.allowed is False
    assert decision.reason == "depth_limit_exceeded"


def test_runtime_limit_exceeded() -> None:
    decision = _decision_for_usage(RuntimeUsage(runtime_seconds=10))

    assert decision.allowed is False
    assert decision.reason == "runtime_limit_exceeded"


def test_cost_limit_exceeded() -> None:
    decision = _decision_for_usage(RuntimeUsage(estimated_cost_usd=0.20))

    assert decision.allowed is False
    assert decision.reason == "cost_limit_exceeded"


def test_per_agent_limit_override_allows_higher_budget() -> None:
    decision = _decision_for_usage(
        RuntimeUsage(tool_calls_used=2, depth_used=3),
        {
            "agents": {
                "ops-agent": {
                    "max_tool_calls": 5,
                    "max_depth": 5,
                }
            }
        },
    )

    assert decision.allowed is True


def test_audit_events_include_runtime_usage_fields() -> None:
    interceptor = AgentInterceptor(
        policy_engine=_policy(),
        audit_logger=AuditLogger(),
        approval_store=ApprovalStore(),
    )

    result = interceptor.intercept(
        InterceptionRequest(
            context=RuntimeContext(
                agent_name="ops-agent",
                tool_name="read_customer",
                arguments={"customer_id": "123"},
                runtime_usage=RuntimeUsage(
                    tool_calls_used=1,
                    depth_used=2,
                    runtime_seconds=4,
                    estimated_cost_usd=0.03,
                ),
            ),
            tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
        )
    )

    assert result == {"customer_id": "123"}
    events = list(interceptor.audit_logger.events())
    assert events
    assert all(event.tool_calls_used == 1 for event in events)
    assert all(event.tool_calls_remaining == 1 for event in events)
    assert all(event.depth_used == 2 for event in events)
    assert all(event.runtime_seconds == 4 for event in events)
    assert all(event.estimated_cost_usd == 0.03 for event in events)


def test_budget_violation_blocks_before_execution() -> None:
    interceptor = AgentInterceptor(
        policy_engine=_policy(),
        audit_logger=AuditLogger(),
        approval_store=ApprovalStore(),
    )

    with pytest.raises(PolicyViolationError, match="tool_call_budget_exceeded"):
        interceptor.intercept(
            InterceptionRequest(
                context=RuntimeContext(
                    agent_name="ops-agent",
                    tool_name="read_customer",
                    arguments={"customer_id": "123"},
                    runtime_usage=RuntimeUsage(tool_calls_used=2),
                ),
                tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
            )
        )

    events = list(interceptor.audit_logger.events())
    assert events[-1].event_type == "tool_blocked"
    assert events[-1].runtime_violations == ["tool_call_budget_exceeded"]


def test_replay_includes_runtime_usage_fields(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    logger.log(
        RuntimeEvent.audit_event(
            event_type="tool_blocked",
            decision="blocked",
            reason="cost_limit_exceeded",
            stage="tool",
            context=RuntimeContext(
                agent_name="ops-agent",
                tool_name="shell_exec",
                trace_id="run-123",
            ),
            budget_status="violated",
            runtime_budget={
                "max_tool_calls": 20,
                "max_depth": 5,
                "max_runtime_seconds": 60,
                "max_cost_usd": 0.05,
            },
            runtime_usage={
                "tool_calls_used": 12,
                "depth_used": 2,
                "runtime_seconds": 14,
                "estimated_cost_usd": 0.10,
            },
            runtime_violations=["cost_limit_exceeded"],
            tool_calls_used=12,
            tool_calls_remaining=8,
            depth_used=2,
            runtime_seconds=14,
            estimated_cost_usd=0.10,
        )
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")
    summary = AuditReplayEngine.summarize_timeline(timeline)
    result = AuditReplayEngine.build_trace_result(timeline)

    assert timeline.entries[0].tool_calls_used == 12
    assert timeline.entries[0].tool_calls_remaining == 8
    assert summary.budget_status == "violated"
    assert summary.usage_summary["estimated_cost_usd"] == 0.10
    assert summary.violations == ["cost_limit_exceeded"]
    assert result.usage_summary["runtime_seconds"] == 14


def test_replay_preserves_backward_compatibility_for_legacy_runtime_events(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text(
        json.dumps(
            {
                "timestamp": "2026-05-10T00:00:00+00:00",
                "event_type": "tool_allowed",
                "decision": "allowed",
                "trace_id": "run-legacy",
                "decision_stage": "decision",
                "agent_name": "demo-agent",
                "tool_name": "read_customer",
                "reason": "Allowed by policy",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-legacy")
    summary = AuditReplayEngine.summarize_timeline(timeline)

    assert timeline.entries[0].runtime_usage is None
    assert summary.usage_summary is None
    assert summary.violations == []
