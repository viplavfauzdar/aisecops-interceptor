import json

import pytest

from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import AUDIT_SCHEMA_VERSION, RuntimeEvent
from aisecops_interceptor.core.models import InstructionProvenance
from aisecops_interceptor.replay.engine import AuditReplayEngine, TraceNotFoundError


def _write_event(
    logger: AuditLogger,
    *,
    trace_id: str,
    event_type: str,
    decision: str,
    tool_name: str | None = None,
    execution_plan_id: str | None = None,
    decision_stage: str | None = None,
    reason: str | None = None,
    provenance: list[InstructionProvenance] | None = None,
) -> None:
    logger.log(
        RuntimeEvent.audit_event(
            event_type=event_type,
            decision=decision,
            reason=reason,
            stage="tool",
            context=RuntimeContext(
                agent_name="demo-agent",
                tool_name=tool_name,
                trace_id=trace_id,
                provenance=provenance or [],
            ),
            execution_plan_id=execution_plan_id,
            decision_stage=decision_stage,
            provenance=provenance,
        )
    )


def test_replay_loads_matching_trace_events_and_ignores_other_trace_ids(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    _write_event(
        logger,
        trace_id="run-123",
        event_type="prompt_allowed",
        decision="allowed",
        decision_stage="input",
        reason="Prompt accepted",
    )
    _write_event(
        logger,
        trace_id="run-999",
        event_type="tool_blocked",
        decision="blocked",
        tool_name="send_email",
        decision_stage="policy",
        reason="Other trace",
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")

    assert [entry.event_type for entry in timeline.entries] == ["prompt_allowed"]
    assert timeline.trace_id == "run-123"


def test_replay_preserves_order_and_groups_by_execution_plan_id(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    _write_event(
        logger,
        trace_id="run-123",
        event_type="plan",
        decision="pending",
        tool_name="restart_service",
        execution_plan_id="plan-1",
        decision_stage="plan",
        reason="Plan created",
    )
    _write_event(
        logger,
        trace_id="run-123",
        event_type="decision",
        decision="require_approval",
        tool_name="restart_service",
        execution_plan_id="plan-1",
        decision_stage="evaluate",
        reason="Approval required",
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")

    assert [entry.event_type for entry in timeline.entries] == ["plan", "decision"]
    assert [entry.event_type for entry in timeline.grouped_entries["plan-1"]] == ["plan", "decision"]


def test_replay_includes_provenance(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    provenance = [
        InstructionProvenance(
            source_type="skill",
            source_name="untrusted_openclaw_skill",
            trust_level="unverified",
        )
    ]
    _write_event(
        logger,
        trace_id="run-123",
        event_type="tool_blocked",
        decision="blocked",
        tool_name="send_email",
        execution_plan_id="plan-2",
        decision_stage="policy",
        reason="Unverified skill provenance",
        provenance=provenance,
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")

    assert timeline.entries[0].provenance[0].source_name == "untrusted_openclaw_skill"
    assert timeline.entries[0].schema_version == AUDIT_SCHEMA_VERSION
    assert timeline.entries[0].event_id is not None


def test_replay_skips_malformed_jsonl_lines_when_recoverable(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    _write_event(
        logger,
        trace_id="run-123",
        event_type="prompt_allowed",
        decision="allowed",
        decision_stage="input",
        reason="Prompt accepted",
    )

    with audit_file.open("a", encoding="utf-8") as handle:
        handle.write("{not-json}\n")

    _write_event(
        logger,
        trace_id="run-123",
        event_type="final_output",
        decision="allowed",
        decision_stage="output",
        reason="Response emitted",
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")

    assert [entry.event_type for entry in timeline.entries] == ["prompt_allowed", "final_output"]
    assert len(timeline.warnings) == 1


def test_replay_raises_for_missing_trace(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    _write_event(
        logger,
        trace_id="run-123",
        event_type="prompt_allowed",
        decision="allowed",
        decision_stage="input",
        reason="Prompt accepted",
    )

    with pytest.raises(TraceNotFoundError):
        AuditReplayEngine().replay_trace(audit_file, "run-missing")


def test_replay_handles_legacy_records_without_schema_or_event_id(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    legacy_record = {
        "timestamp": "2026-05-10T00:00:00+00:00",
        "event_type": "tool_blocked",
        "decision": "blocked",
        "trace_id": "run-legacy",
        "decision_stage": "policy",
        "agent_name": "demo-agent",
        "tool_name": "send_email",
        "reason": "Legacy policy block",
        "provenance": [],
    }
    audit_file.write_text(json.dumps(legacy_record) + "\n", encoding="utf-8")

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-legacy")

    assert timeline.entries[0].schema_version is None
    assert timeline.entries[0].event_id is None


def test_replay_summary_includes_provenance_trust_and_schema_versions(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    provenance = [
        InstructionProvenance(
            source_type="skill",
            source_name="untrusted_openclaw_skill",
            trust_level="unverified",
        ),
        InstructionProvenance(
            source_type="system_prompt",
            source_name="ops_runbook",
            trust_level="trusted",
        ),
    ]
    _write_event(
        logger,
        trace_id="run-123",
        event_type="tool_blocked",
        decision="blocked",
        tool_name="send_email",
        execution_plan_id="plan-2",
        decision_stage="policy",
        reason="Unverified skill provenance",
        provenance=provenance,
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")
    summary = AuditReplayEngine.summarize_timeline(timeline)

    assert summary.trace_id == "run-123"
    assert summary.event_count == 1
    assert summary.final_decision == "blocked"
    assert summary.tool_name == "send_email"
    assert summary.final_reason == "Unverified skill provenance"
    assert summary.provenance_trust_summary == {"trusted": 1, "unverified": 1}
    assert summary.schema_versions_observed == [AUDIT_SCHEMA_VERSION]


def test_replay_trace_result_includes_execution_plans_and_final_fields(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    _write_event(
        logger,
        trace_id="run-123",
        event_type="plan",
        decision="pending",
        tool_name="send_email",
        execution_plan_id="plan-1",
        decision_stage="plan",
        reason="Execution plan created",
    )
    _write_event(
        logger,
        trace_id="run-123",
        event_type="tool_blocked",
        decision="blocked",
        tool_name="send_email",
        execution_plan_id="plan-1",
        decision_stage="policy",
        reason="Rule blocked tool 'send_email'",
        provenance=[
            InstructionProvenance(
                source_type="skill",
                source_name="untrusted_openclaw_skill",
                trust_level="unverified",
            )
        ],
    )

    timeline = AuditReplayEngine().replay_trace(audit_file, "run-123")
    result = AuditReplayEngine.build_trace_result(timeline)

    assert result.trace_id == "run-123"
    assert result.event_count == 2
    assert result.execution_plan_ids == ["plan-1"]
    assert result.final_decision == "blocked"
    assert result.final_reason == "Rule blocked tool 'send_email'"
    assert result.provenance_summary == {"unverified": 1}


def test_list_traces_filters_and_applies_limit(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(audit_file))
    _write_event(
        logger,
        trace_id="run-1",
        event_type="tool_blocked",
        decision="blocked",
        tool_name="send_email",
        decision_stage="policy",
        reason="Rule blocked tool 'send_email'",
        provenance=[
            InstructionProvenance(
                source_type="skill",
                source_name="untrusted_openclaw_skill",
                trust_level="unverified",
            )
        ],
    )
    _write_event(
        logger,
        trace_id="run-2",
        event_type="tool_allowed",
        decision="allowed",
        tool_name="read_customer",
        decision_stage="decision",
        reason="Allowed by policy",
        provenance=[
            InstructionProvenance(
                source_type="system_prompt",
                source_name="ops_runbook",
                trust_level="trusted",
            )
        ],
    )

    engine = AuditReplayEngine()
    summaries = engine.list_traces(audit_file, limit=1)
    blocked = engine.list_traces(audit_file, decision="blocked")
    by_tool = engine.list_traces(audit_file, tool_name="read_customer")
    by_trust = engine.list_traces(audit_file, provenance_trust="unverified")

    assert len(summaries) == 1
    assert blocked[0].trace_id == "run-1"
    assert by_tool[0].trace_id == "run-2"
    assert by_trust[0].trace_id == "run-1"


def test_list_traces_returns_empty_for_missing_audit_file(tmp_path) -> None:
    audit_file = tmp_path / "missing.jsonl"

    summaries = AuditReplayEngine().list_traces(audit_file)

    assert summaries == []
