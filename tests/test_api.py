from fastapi.testclient import TestClient

from aisecops_interceptor.api.main import app, audit
from aisecops_interceptor.core.audit import SinkFailure


client = TestClient(app)


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
    original_failures = list(audit.sink_failures())
    audit._sink_failures.append(
        SinkFailure(
            sink_type="WebhookEventSink",
            event_type="tool_executed",
            error_type="HTTPError",
            message="boom",
        )
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
        audit._sink_failures[:] = original_failures
