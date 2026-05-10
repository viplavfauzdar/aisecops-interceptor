import asyncio

from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.models import ExecutionPlan, InstructionProvenance
from examples import hack_the_agent_demo


def test_instruction_provenance_serialization_round_trip() -> None:
    item = InstructionProvenance(
        source_type="skill",
        source_name="untrusted_openclaw_skill",
        source_hash="abc123",
        origin_uri="skill://openclaw/untrusted",
        trust_level="unverified",
        metadata={"channel": "demo"},
    )

    restored = InstructionProvenance.from_dict(item.to_dict())

    assert restored == item


def test_execution_plan_accepts_provenance() -> None:
    provenance = [
        InstructionProvenance(
            source_type="user_prompt",
            source_name="user",
            trust_level="external",
        )
    ]
    plan = ExecutionPlan(
        context=RuntimeContext(agent_name="demo-agent", tool_name="read_customer"),
        tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
        provenance=provenance,
    )

    assert plan.provenance == provenance
    assert plan.execution_plan_id


def test_audit_event_persists_provenance(tmp_path) -> None:
    logger = AuditLogger(log_path=str(tmp_path / "runtime-events.jsonl"))
    provenance = [
        InstructionProvenance(
            source_type="skill",
            source_name="untrusted_openclaw_skill",
            trust_level="unverified",
        )
    ]
    context = RuntimeContext(
        agent_name="demo-agent",
        tool_name="restart_service",
        provenance=provenance,
    )

    logger.log(
        RuntimeEvent.audit_event(
            event_type="decision",
            decision="blocked",
            reason="Blocked for replay test",
            stage="tool",
            context=context,
            execution_plan_id="plan-123",
            decision_stage="evaluate",
        )
    )

    persisted = list(logger.persisted_events())
    assert len(persisted) == 1
    assert persisted[0].trace_id is not None
    assert persisted[0].execution_plan_id == "plan-123"
    assert persisted[0].decision_stage == "evaluate"
    assert persisted[0].provenance is not None
    assert persisted[0].provenance[0].source_name == "untrusted_openclaw_skill"


def test_missing_provenance_does_not_break_existing_flow(tmp_path) -> None:
    logger = AuditLogger(log_path=str(tmp_path / "runtime-events.jsonl"))
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")

    logger.log(
        RuntimeEvent.tool_event(
            event_type="tool_allowed",
            decision="allowed",
            context=context,
            allowed=True,
            reason="Allowed without provenance",
            execution_plan_id="plan-no-prov",
            decision_stage="decision",
        )
    )

    persisted = list(logger.persisted_events())
    assert len(persisted) == 1
    assert persisted[0].provenance is None
    assert persisted[0].execution_plan_id == "plan-no-prov"


def test_hack_the_agent_demo_emits_provenance_metadata(tmp_path) -> None:
    audit_path = tmp_path / "hack-the-agent-runtime-events.jsonl"

    asyncio.run(hack_the_agent_demo.main(audit_path=audit_path))

    logger = AuditLogger(log_path=str(audit_path))
    events = list(logger.persisted_events())
    assert any(
        event.provenance
        and any(
            item.source_type == "skill"
            and item.source_name == "untrusted_openclaw_skill"
            and item.trust_level == "unverified"
            for item in event.provenance
        )
        for event in events
    )
