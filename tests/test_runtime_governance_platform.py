import json

from fastapi.testclient import TestClient

from aisecops_interceptor.api.main import app
from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.explanation import explain_governance_decision
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest, RuntimeUsage
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.evidence.export import EvidenceExporter
from aisecops_interceptor.replay.diff import ReplayDiffEngine
from aisecops_interceptor.replay.engine import AuditReplayEngine


def _interceptor(audit_file, config=None):
    audit = AuditLogger(log_path=str(audit_file))
    interceptor = AgentInterceptor(
        policy_engine=PolicyEngine(config or {"blocked_tools": []}),
        audit_logger=audit,
        approval_store=ApprovalStore(),
        capability_registry=CapabilityRegistry(),
    )
    return interceptor, audit


def _run_trace(audit_file, *, tool_name="read_customer", config=None, dry_run=False, registry=None):
    interceptor, _audit = _interceptor(audit_file, config=config)
    tool_registry = registry or {
        "read_customer": lambda customer_id="123": {"customer_id": customer_id},
        "restart_service": lambda service="orders": {"service": service},
        "shell_exec": lambda command="id": {"command": command},
    }
    context = RuntimeContext(agent_name="ops-agent", tool_name=tool_name, arguments={})
    plan = interceptor.plan(InterceptionRequest(context=context, tool_registry=tool_registry, dry_run=dry_run))
    interceptor.evaluate(plan)
    try:
        interceptor.execute_plan(plan)
    except Exception:
        pass
    return context.trace_id


def test_replay_diff_matched_execution(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = _run_trace(audit_file, tool_name="read_customer")

    diff = ReplayDiffEngine().diff_trace(audit_file, trace_id)

    assert diff.governance_result == "matched"
    assert diff.policy_decision == "allowed"
    assert diff.execution_outcome == "executed"
    assert diff.mismatches == []


def test_replay_diff_blocked_execution(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = _run_trace(audit_file, tool_name="shell_exec", config={"blocked_tools": ["shell_exec"]})

    diff = ReplayDiffEngine().diff_trace(audit_file, trace_id)

    assert diff.governance_result == "blocked"
    assert diff.policy_decision == "blocked"
    assert diff.execution_outcome == "not_performed"


def test_replay_diff_approval_enforced(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = _run_trace(
        audit_file,
        tool_name="restart_service",
        config={"agents": {"ops-agent": {"approval_required_tools": ["restart_service"]}}},
    )

    diff = ReplayDiffEngine().diff_trace(audit_file, trace_id)

    assert diff.governance_result == "enforced"
    assert diff.policy_decision == "require_approval"
    assert diff.execution_outcome == "not_performed"


def test_replay_diff_detects_violation_when_blocked_action_executed(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = "trace-violation"
    context = RuntimeContext(agent_name="ops-agent", tool_name="shell_exec", trace_id=trace_id)
    audit = AuditLogger(log_path=str(audit_file))
    audit.log(RuntimeEvent.audit_event(event_type="plan", decision="pending", context=context, plan_intent="shell_exec"))
    audit.log(RuntimeEvent.audit_event(event_type="decision", decision="blocked", context=context, reason="blocked"))
    audit.log(RuntimeEvent.tool_event(event_type="tool_executed", decision="allowed", context=context, allowed=True, reason="ran"))

    diff = ReplayDiffEngine().diff_trace(audit_file, trace_id)

    assert diff.governance_result == "violation"
    assert diff.mismatches[0].type == "blocked_execution_occurred"
    assert diff.mismatches[0].severity == "critical"


def test_agent_identity_config_load_and_limits_override():
    engine = PolicyEngine(
        {
            "agent_limits": {"max_tool_calls": 2, "max_cost_usd": 1.0},
            "agents": {
                "ops-agent": {
                    "agent_id": "agent-ops",
                    "trust_level": "internal",
                    "environment": "local",
                    "allowed_capabilities": ["infra.restart"],
                    "max_tool_calls": 50,
                    "max_cost_usd": 10.0,
                }
            },
        }
    )

    identity = engine.agent_identity_for("ops-agent")
    budget = engine.runtime_budget_for_agent("ops-agent")

    assert identity is not None
    assert identity.agent_id == "agent-ops"
    assert identity.allowed_capabilities == ["infra.restart"]
    assert budget.max_tool_calls == 50
    assert budget.max_cost_usd == 10.0


def test_agent_identity_enriches_audit_and_replay_metadata(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = _run_trace(
        audit_file,
        tool_name="read_customer",
        config={
            "agents": {
                "ops-agent": {
                    "agent_id": "agent-ops",
                    "trust_level": "internal",
                    "environment": "local",
                }
            }
        },
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, trace_id)
    summary = AuditReplayEngine.summarize_timeline(timeline)

    assert timeline.entries[-1].agent_id == "agent-ops"
    assert summary.agent_id == "agent-ops"
    assert summary.agent_trust_level == "internal"
    assert summary.agent_environment == "local"


def test_evidence_export_json_and_markdown(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = _run_trace(audit_file, tool_name="read_customer")
    exporter = EvidenceExporter()

    json_payload = exporter.export(audit_file=audit_file, trace_id=trace_id, output_format="json")
    markdown = exporter.export(audit_file=audit_file, trace_id=trace_id, output_format="markdown")

    parsed = json.loads(json_payload)
    assert parsed["trace_id"] == trace_id
    assert parsed["final_governance_result"] == "matched"
    assert "# AISecOps Governance Evidence" in markdown
    assert "Replay Diff" in markdown


def test_risk_explanation_helper():
    assert explain_governance_decision(tool_name="shell_exec", capability="system.shell", decision="blocked") == (
        "Policy blocked shell_exec because system.shell is not allowed for this agent."
    )
    assert "max_tool_calls" in explain_governance_decision(
        tool_name="read_customer",
        decision="blocked",
        budget_violations=["max_tool_calls"],
    )


def test_new_replay_diff_api(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.jsonl"
    trace_id = _run_trace(audit_file, tool_name="read_customer")
    monkeypatch.setattr("aisecops_interceptor.api.main.replay_audit_file_path", lambda: str(audit_file))

    response = TestClient(app).get(f"/replay/{trace_id}/diff")

    assert response.status_code == 200
    payload = response.json()
    assert payload["governance_result"] == "matched"
    for field in (
        "trace_id",
        "plan_id",
        "planned_tool",
        "planned_intent",
        "planned_capabilities",
        "planned_risk_level",
        "policy_decision",
        "execution_outcome",
        "governance_result",
        "mismatches",
        "violations",
        "summary",
    ):
        assert field in payload


def test_replay_diff_openapi_schema_documents_response():
    schema = TestClient(app).get("/openapi.json").json()
    response_schema = schema["paths"]["/replay/{trace_id}/diff"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]

    assert response_schema["$ref"] == "#/components/schemas/ReplayDiffResponseModel"
    diff_schema = schema["components"]["schemas"]["ReplayDiffResponseModel"]
    mismatch_ref = diff_schema["properties"]["mismatches"]["items"]["$ref"]
    mismatch_schema = schema["components"]["schemas"][mismatch_ref.rsplit("/", 1)[-1]]
    for field in (
        "trace_id",
        "plan_id",
        "planned_tool",
        "planned_intent",
        "planned_capabilities",
        "planned_risk_level",
        "policy_decision",
        "execution_outcome",
        "governance_result",
        "mismatches",
        "violations",
        "summary",
    ):
        assert field in diff_schema["properties"]
    for field in ("type", "expected", "actual", "severity", "reason"):
        assert field in mismatch_schema["properties"]


def test_replay_diff_backward_compatibility_with_old_audit_events(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "allowed": True,
                "reason": "legacy allowed",
                "agent_name": "legacy-agent",
                "tool_name": "read_customer",
                "trace_id": "legacy-trace",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    diff = ReplayDiffEngine().diff_trace(audit_file, "legacy-trace")

    assert diff.trace_id == "legacy-trace"
    assert diff.governance_result in {"observed", "matched"}
