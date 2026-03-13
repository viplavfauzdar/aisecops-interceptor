import json

from fastapi.testclient import TestClient

from aisecops_interceptor.api.main import app, audit
from aisecops_interceptor.core.audit import SinkFailure


client = TestClient(app)


def _set_sink_failures(failures: list[SinkFailure]) -> None:
    audit._sink_failures[:] = failures
    if audit.sink_failure_log_path is None:
        return
    audit.sink_failure_log_path.parent.mkdir(parents=True, exist_ok=True)
    with audit.sink_failure_log_path.open("w", encoding="utf-8") as f:
        for failure in failures:
            f.write(json.dumps(failure.to_dict()) + "\n")


def _capture_sink_failure_state() -> tuple[list[SinkFailure], str | None]:
    persisted = None
    if audit.sink_failure_log_path is not None and audit.sink_failure_log_path.exists():
        persisted = audit.sink_failure_log_path.read_text(encoding="utf-8")
    return list(audit.sink_failures()), persisted


def _restore_sink_failure_state(failures: list[SinkFailure], persisted: str | None) -> None:
    audit._sink_failures[:] = failures
    if audit.sink_failure_log_path is None:
        return
    audit.sink_failure_log_path.parent.mkdir(parents=True, exist_ok=True)
    if persisted is None:
        if audit.sink_failure_log_path.exists():
            audit.sink_failure_log_path.unlink()
        return
    audit.sink_failure_log_path.write_text(persisted, encoding="utf-8")


def test_execute_endpoint_allows_and_serializes_audit_event() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "sales_agent",
            "tool_name": "read_customer",
            "arguments": {"customer_id": "123"},
        },
    )

    assert response.status_code == 200
    assert response.json()["result"] == {"customer_id": "123", "status": "active"}

    audit_response = client.get("/audit")
    assert audit_response.status_code == 200
    assert any(
        event["tool_name"] == "read_customer" and event["event_type"] == "tool_executed"
        for event in audit_response.json()
    )


def test_approval_flow_serializes_pending_requests() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "ops_agent",
            "tool_name": "restart_service",
            "arguments": {"service": "orders"},
        },
    )

    assert response.status_code == 202
    approval_id = response.json()["detail"]["approval_id"]

    approvals_response = client.get("/approvals")
    assert approvals_response.status_code == 200
    assert any(item["approval_id"] == approval_id for item in approvals_response.json())

    audit_response = client.get("/audit")
    assert audit_response.status_code == 200
    assert any(
        event["approval_id"] == approval_id and event["event_type"] == "approval_required"
        for event in audit_response.json()
    )


def test_audit_endpoint_filters_by_event_type() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "sales_agent",
            "tool_name": "read_customer",
            "arguments": {"customer_id": "123"},
        },
    )
    assert response.status_code == 200

    audit_response = client.get("/audit", params={"event_type": "tool_executed"})
    assert audit_response.status_code == 200
    events = audit_response.json()
    assert events
    assert all(event["event_type"] == "tool_executed" for event in events)


def test_audit_endpoint_filters_by_stage() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "sales_agent",
            "tool_name": "read_customer",
            "arguments": {"customer_id": "123"},
        },
    )
    assert response.status_code == 200

    audit_response = client.get("/audit", params={"stage": "tool"})
    assert audit_response.status_code == 200
    events = audit_response.json()
    assert events
    assert all(event["stage"] == "tool" for event in events)


def test_audit_endpoint_filters_by_correlation_id() -> None:
    response = client.post(
        "/openclaw/execute",
        json={
            "agent_name": "openclaw_agent",
            "tool_name": "get_deployment_status",
            "arguments": {"service": "payments"},
            "correlation_id": "corr-api-1",
        },
    )
    assert response.status_code == 200

    audit_response = client.get("/audit", params={"correlation_id": "corr-api-1"})
    assert audit_response.status_code == 200
    events = audit_response.json()
    assert events
    assert all(event["correlation_id"] == "corr-api-1" for event in events)


def test_audit_endpoint_applies_limit() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "sales_agent",
            "tool_name": "read_customer",
            "arguments": {"customer_id": "123"},
        },
    )
    assert response.status_code == 200

    audit_response = client.get("/audit", params={"limit": 1})
    assert audit_response.status_code == 200
    assert len(audit_response.json()) == 1


def test_audit_failures_endpoint_returns_recorded_sink_failures() -> None:
    original_failures, original_persisted = _capture_sink_failure_state()
    _set_sink_failures(
        [
            SinkFailure(
                sink_type="WebhookEventSink",
                event_type="tool_executed",
                error_type="HTTPError",
                message="boom",
            )
        ]
    )

    try:
        response = client.get("/audit/failures")
        assert response.status_code == 200
        failures = response.json()
        assert any(
            item["sink_type"] == "WebhookEventSink"
            and item["event_type"] == "tool_executed"
            and item["error_type"] == "HTTPError"
            for item in failures
        )
    finally:
        _restore_sink_failure_state(original_failures, original_persisted)


def test_audit_failures_endpoint_filters_by_sink_type() -> None:
    original_failures, original_persisted = _capture_sink_failure_state()
    _set_sink_failures(
        [
            SinkFailure("WebhookEventSink", "tool_executed", "HTTPError", "boom"),
            SinkFailure("FileEventSink", "tool_allowed", "OSError", "disk full"),
        ]
    )
    try:
        response = client.get("/audit/failures", params={"sink_type": "WebhookEventSink"})
        assert response.status_code == 200
        failures = response.json()
        assert failures
        assert all(item["sink_type"] == "WebhookEventSink" for item in failures)
    finally:
        _restore_sink_failure_state(original_failures, original_persisted)


def test_audit_failures_endpoint_filters_by_event_type() -> None:
    original_failures, original_persisted = _capture_sink_failure_state()
    _set_sink_failures(
        [
            SinkFailure("WebhookEventSink", "tool_executed", "HTTPError", "boom"),
            SinkFailure("WebhookEventSink", "tool_allowed", "HTTPError", "timeout"),
        ]
    )
    try:
        response = client.get("/audit/failures", params={"event_type": "tool_allowed"})
        assert response.status_code == 200
        failures = response.json()
        assert failures
        assert all(item["event_type"] == "tool_allowed" for item in failures)
    finally:
        _restore_sink_failure_state(original_failures, original_persisted)


def test_audit_failures_endpoint_filters_by_error_type() -> None:
    original_failures, original_persisted = _capture_sink_failure_state()
    _set_sink_failures(
        [
            SinkFailure("WebhookEventSink", "tool_executed", "HTTPError", "boom"),
            SinkFailure("FileEventSink", "tool_allowed", "OSError", "disk full"),
        ]
    )
    try:
        response = client.get("/audit/failures", params={"error_type": "OSError"})
        assert response.status_code == 200
        failures = response.json()
        assert failures
        assert all(item["error_type"] == "OSError" for item in failures)
    finally:
        _restore_sink_failure_state(original_failures, original_persisted)


def test_audit_failures_endpoint_applies_limit() -> None:
    original_failures, original_persisted = _capture_sink_failure_state()
    _set_sink_failures(
        [
            SinkFailure("WebhookEventSink", "tool_executed", "HTTPError", "boom"),
            SinkFailure("FileEventSink", "tool_allowed", "OSError", "disk full"),
        ]
    )
    try:
        response = client.get("/audit/failures", params={"limit": 1})
        assert response.status_code == 200
        assert len(response.json()) == 1
    finally:
        _restore_sink_failure_state(original_failures, original_persisted)
