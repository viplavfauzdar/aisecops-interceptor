from fastapi.testclient import TestClient

from aisecops_interceptor.api.main import app


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
    assert any(event["tool_name"] == "read_customer" for event in audit_response.json())


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
