from unittest.mock import Mock, patch

import httpx

from aisecops_interceptor.core.audit import AuditLogger, SinkFailure
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.event_sink import FileEventSink, InMemoryEventSink, WebhookEventSink
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


def test_webhook_event_sink_posts_runtime_event_json() -> None:
    sink = WebhookEventSink("https://example.com/webhook", timeout=2.5)
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")
    event = RuntimeEvent.tool_event(
        event_type="tool_allowed",
        decision="allowed",
        context=context,
        allowed=True,
        reason="Allowed by policy",
    )
    response = Mock()
    response.raise_for_status = Mock()

    with patch("aisecops_interceptor.core.event_sink.httpx.post", return_value=response) as mock_post:
        sink.emit(event)

    mock_post.assert_called_once_with(
        "https://example.com/webhook",
        json=event.to_dict(),
        timeout=2.5,
    )
    response.raise_for_status.assert_called_once_with()


def test_webhook_sink_coexists_with_file_and_memory_sinks(tmp_path) -> None:
    file_sink = FileEventSink(str(tmp_path / "runtime-events.jsonl"))
    extra_memory_sink = InMemoryEventSink()
    webhook_sink = WebhookEventSink("https://example.com/webhook")
    logger = AuditLogger(sinks=[file_sink, extra_memory_sink, webhook_sink])
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")
    event = RuntimeEvent.tool_event(
        event_type="tool_executed",
        decision="allowed",
        context=context,
        allowed=True,
        reason="Tool executed",
    )
    response = Mock(spec=httpx.Response)
    response.raise_for_status = Mock()

    with patch("aisecops_interceptor.core.event_sink.httpx.post", return_value=response) as mock_post:
        logger.log(event)

    assert [item.event_type for item in logger.events()] == ["tool_executed"]
    assert [item.event_type for item in extra_memory_sink.events()] == ["tool_executed"]
    assert [item.event_type for item in file_sink.events()] == ["tool_executed"]
    mock_post.assert_called_once()


def test_failing_webhook_sink_does_not_stop_file_sink(tmp_path) -> None:
    file_sink = FileEventSink(str(tmp_path / "runtime-events.jsonl"))
    webhook_sink = WebhookEventSink("https://example.com/webhook")
    logger = AuditLogger(
        sinks=[file_sink, webhook_sink],
        sink_failure_log_path=str(tmp_path / "sink-failures.jsonl"),
    )
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")
    event = RuntimeEvent.tool_event(
        event_type="tool_executed",
        decision="allowed",
        context=context,
        allowed=True,
        reason="Tool executed",
    )

    with patch(
        "aisecops_interceptor.core.event_sink.httpx.post",
        side_effect=httpx.HTTPError("boom"),
    ):
        logger.log(event)

    assert [item.event_type for item in logger.events()] == ["tool_executed"]
    assert [item.event_type for item in file_sink.events()] == ["tool_executed"]
    failures = list(logger.sink_failures())
    assert len(failures) == 1
    assert failures[0].sink_type == "WebhookEventSink"
    assert failures[0].event_type == "tool_executed"
    assert failures[0].error_type == "HTTPError"
    persisted_failures = list(logger.persisted_sink_failures())
    assert len(persisted_failures) == 1
    assert persisted_failures[0].sink_type == "WebhookEventSink"
    assert persisted_failures[0].event_type == "tool_executed"


def test_failing_webhook_sink_does_not_stop_memory_sink(tmp_path) -> None:
    extra_memory_sink = InMemoryEventSink()
    webhook_sink = WebhookEventSink("https://example.com/webhook")
    logger = AuditLogger(
        sinks=[extra_memory_sink, webhook_sink],
        sink_failure_log_path=str(tmp_path / "sink-failures.jsonl"),
    )
    context = RuntimeContext(agent_name="demo-agent", tool_name="read_customer")
    event = RuntimeEvent.tool_event(
        event_type="tool_allowed",
        decision="allowed",
        context=context,
        allowed=True,
        reason="Allowed by policy",
    )

    with patch(
        "aisecops_interceptor.core.event_sink.httpx.post",
        side_effect=httpx.HTTPError("boom"),
    ):
        logger.log(event)

    assert [item.event_type for item in logger.events()] == ["tool_allowed"]
    assert [item.event_type for item in extra_memory_sink.events()] == ["tool_allowed"]
    failures = list(logger.sink_failures())
    assert len(failures) == 1
    assert failures[0].sink_type == "WebhookEventSink"
    assert failures[0].event_type == "tool_allowed"
    assert failures[0].error_type == "HTTPError"
    persisted_failures = list(logger.persisted_sink_failures())
    assert len(persisted_failures) == 1
    assert persisted_failures[0].sink_type == "WebhookEventSink"
    assert persisted_failures[0].event_type == "tool_allowed"


def test_sink_failure_is_persisted_to_jsonl(tmp_path) -> None:
    logger = AuditLogger(sink_failure_log_path=str(tmp_path / "sink-failures.jsonl"))
    failure = SinkFailure(
        sink_type="WebhookEventSink",
        event_type="tool_blocked",
        error_type="HTTPError",
        message="boom",
    )
    logger.record_sink_failure(failure)

    persisted_failures = list(logger.persisted_sink_failures())
    assert len(persisted_failures) == 1
    assert persisted_failures[0] == failure
