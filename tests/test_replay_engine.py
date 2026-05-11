import json

import pytest

from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
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
