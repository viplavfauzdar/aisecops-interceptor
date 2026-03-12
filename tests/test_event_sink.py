from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.event_sink import FileEventSink, InMemoryEventSink
from aisecops_interceptor.core.events import RuntimeEvent


def test_audit_logger_emits_to_all_sinks(tmp_path) -> None:
    file_sink = FileEventSink(str(tmp_path / "runtime-events.jsonl"))
    extra_memory_sink = InMemoryEventSink()
    logger = AuditLogger(sinks=[file_sink, extra_memory_sink])
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")

    event = RuntimeEvent.tool_event(
        event_type="tool_allowed",
        decision="allowed",
        context=context,
        allowed=True,
        reason="Allowed by policy",
    )

    logger.log(event)

    assert [item.event_type for item in logger.events()] == ["tool_allowed"]
    assert [item.event_type for item in extra_memory_sink.events()] == ["tool_allowed"]
    assert [item.event_type for item in file_sink.events()] == ["tool_allowed"]


def test_log_path_persistence_behavior_is_unchanged(tmp_path) -> None:
    logger = AuditLogger(log_path=str(tmp_path / "runtime-events.jsonl"))
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")

    event = RuntimeEvent.tool_event(
        event_type="tool_executed",
        decision="allowed",
        context=context,
        allowed=True,
        reason="Tool executed",
    )

    logger.log(event)

    assert [item.event_type for item in logger.events()] == ["tool_executed"]
    assert [item.event_type for item in logger.persisted_events()] == ["tool_executed"]
