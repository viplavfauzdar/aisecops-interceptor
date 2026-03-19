import json

from fastapi.testclient import TestClient

from aisecops_interceptor.api.main import app, audit, tool_registry
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
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["decision"] == "allow"
    assert payload["reason"] == "Tool 'read_customer' allowed with audit monitoring"
    assert payload["data"] == {"customer_id": "123", "status": "active"}
    assert payload["trace"]["final_decision"] == "allowed"

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
    payload = response.json()
    assert payload["status"] == "require_approval"
    assert payload["decision"] == "require_approval"
    assert payload["data"]["approval_id"]
    approval_id = payload["data"]["approval_id"]
    assert payload["trace"]["final_decision"] == "require_approval"

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


def test_explain_endpoint_returns_structured_decision() -> None:
    response = client.post(
        "/explain",
        json={
            "agent_name": "ops_agent",
            "tool_name": "restart_service",
            "arguments": {"service": "orders"},
        },
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "require_approval"
    assert payload["decision"] == "require_approval"
    assert payload["reason"] == "Tool 'restart_service' requires human approval"
    assert payload["data"] is None
    assert payload["trace"]["capability_result"] == "not_applicable"
    assert payload["trace"]["policy_result"] == "require_approval"
    assert payload["trace"]["final_decision"] == "require_approval"
    assert any("risk: high" in item for item in payload["trace"]["reason_chain"])
    assert any("cap_service_ops" in item for item in payload["trace"]["reason_chain"])


def test_explain_endpoint_does_not_execute_tool() -> None:
    executed = {"called": False}

    def sentinel_read_customer(customer_id: str) -> dict[str, str]:
        executed["called"] = True
        return {"customer_id": customer_id}

    previous_tool = tool_registry["read_customer"]
    tool_registry["read_customer"] = sentinel_read_customer
    try:
        response = client.post(
            "/explain",
            json={
                "agent_name": "sales_agent",
                "tool_name": "read_customer",
                "arguments": {"customer_id": "123"},
            },
        )
        assert response.status_code == 200
        assert executed["called"] is False
    finally:
        tool_registry["read_customer"] = previous_tool


def test_explain_endpoint_includes_reason_chain() -> None:
    response = client.post(
        "/explain",
        json={
            "agent_name": "sales_agent",
            "tool_name": "shell_exec",
            "arguments": {"command": "rm -rf /tmp/demo"},
        },
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["status"] == "blocked"
    assert payload["decision"] == "block"
    assert payload["trace"]["final_decision"] == "blocked"
    assert any("Capability gate skipped" in item or "globally blocked" in item for item in payload["trace"]["reason_chain"])
    assert any("globally blocked" in item for item in payload["trace"]["reason_chain"])


def test_execute_endpoint_returns_structured_block_response() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "sales_agent",
            "tool_name": "shell_exec",
            "arguments": {"command": "rm -rf /tmp/demo"},
        },
    )

    assert response.status_code == 403
    assert response.json() == {
        "status": "blocked",
        "decision": "block",
        "reason": "Tool 'shell_exec' is globally blocked",
        "data": None,
        "trace": {
            "reason_chain": [
                "Capability gate skipped because no capabilities were provided",
                "Tool 'shell_exec' is globally blocked",
            ],
            "capability_result": "not_applicable",
            "policy_result": "blocked",
            "final_decision": "blocked",
            "capability_metadata": None,
        },
    }


def test_explain_endpoint_returns_structured_not_found_response() -> None:
    response = client.post(
        "/explain",
        json={
            "agent_name": "sales_agent",
            "tool_name": "missing_tool",
            "arguments": {},
        },
    )

    assert response.status_code == 404
    assert response.json() == {
        "status": "blocked",
        "decision": "block",
        "reason": "Tool 'missing_tool' not found",
        "data": None,
        "trace": None,
    }


def test_execute_endpoint_dry_run_does_not_execute_tool() -> None:
    executed = {"called": False}

    def sentinel_read_customer(customer_id: str) -> dict[str, str]:
        executed["called"] = True
        return {"customer_id": customer_id}

    previous_tool = tool_registry["read_customer"]
    tool_registry["read_customer"] = sentinel_read_customer
    try:
        response = client.post(
            "/execute",
            json={
                "agent_name": "sales_agent",
                "tool_name": "read_customer",
                "arguments": {"customer_id": "123"},
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "dry_run"
        assert payload["decision"] == "allow"
        assert payload["data"]["would_allow"] is True
        assert payload["data"]["would_block"] is False
        assert payload["data"]["would_require_approval"] is False
        assert payload["trace"]["final_decision"] == "allowed"
        assert executed["called"] is False
    finally:
        tool_registry["read_customer"] = previous_tool


def test_execute_endpoint_dry_run_returns_approval_decision() -> None:
    response = client.post(
        "/execute",
        json={
            "agent_name": "ops_agent",
            "tool_name": "restart_service",
            "arguments": {"service": "orders"},
            "dry_run": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "dry_run"
    assert payload["decision"] == "require_approval"
    assert payload["data"]["would_allow"] is False
    assert payload["data"]["would_block"] is False
    assert payload["data"]["would_require_approval"] is True
    assert payload["trace"]["final_decision"] == "require_approval"


def test_openapi_includes_execute_and_explain_examples() -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    execute_operation = schema["paths"]["/execute"]["post"]
    explain_operation = schema["paths"]["/explain"]["post"]

    execute_examples = execute_operation["requestBody"]["content"]["application/json"]["examples"]
    assert "safe_tool_execution" in execute_examples
    assert "approval_required_tool" in execute_examples
    assert "dry_run_request" in execute_examples

    execute_response_examples = execute_operation["responses"]["200"]["content"]["application/json"]["examples"]
    assert "allowed_execution" in execute_response_examples
    assert "dry_run_result" in execute_response_examples

    approval_response = execute_operation["responses"]["202"]["content"]["application/json"]["example"]
    assert approval_response["status"] == "require_approval"
    assert approval_response["decision"] == "require_approval"
    assert "data" in approval_response

    blocked_response = execute_operation["responses"]["403"]["content"]["application/json"]["examples"]["policy_block"][
        "value"
    ]
    assert blocked_response["status"] == "blocked"
    assert blocked_response["decision"] == "block"

    not_found_response = execute_operation["responses"]["404"]["content"]["application/json"]["example"]
    assert not_found_response["status"] == "blocked"
    assert not_found_response["decision"] == "block"

    explain_success = explain_operation["responses"]["200"]["content"]["application/json"]["examples"]["allowed"]["value"]
    assert explain_success["status"] == "success"
    assert explain_success["decision"] == "allow"
    assert explain_success["trace"]["final_decision"] == "allowed"

    explain_approval = explain_operation["responses"]["202"]["content"]["application/json"]["example"]
    assert explain_approval["status"] == "require_approval"
    assert explain_approval["trace"]["final_decision"] == "require_approval"

    explain_blocked = explain_operation["responses"]["403"]["content"]["application/json"]["examples"]["blocked"]["value"]
    assert explain_blocked["status"] == "blocked"
    assert explain_blocked["decision"] == "block"
    assert explain_blocked["trace"]["final_decision"] == "blocked"

    explain_not_found = explain_operation["responses"]["404"]["content"]["application/json"]["example"]
    assert explain_not_found["status"] == "blocked"


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
