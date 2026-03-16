from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import DryRunResult, InterceptionRequest, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


def make_interceptor() -> AgentInterceptor:
    policy = PolicyEngine(
        {
            "blocked_tools": ["delete_database"],
            "dangerous_argument_patterns": ["drop table"],
            "agents": {
                "sales_agent": {
                    "allowed_tools": ["read_customer", "send_email"],
                },
                "ops_agent": {
                    "allowed_tools": ["get_deployment_status", "restart_service"],
                    "approval_required_tools": ["restart_service"],
                },
            },
        }
    )
    return AgentInterceptor(policy_engine=policy, audit_logger=AuditLogger(), approval_store=ApprovalStore())


def make_sensitivity_interceptor() -> AgentInterceptor:
    policy = PolicyEngine(
        {
            "data_classification": {
                "blocked_sensitivity_levels": ["high"],
            },
            "agents": {
                "sales_agent": {
                    "allowed_tools": ["read_customer"],
                },
            },
        }
    )
    return AgentInterceptor(policy_engine=policy, audit_logger=AuditLogger(), approval_store=ApprovalStore())


def test_allows_permitted_tool_call() -> None:
    interceptor = make_interceptor()
    result = interceptor.execute(
        agent_name="sales_agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
        tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
    )
    assert result == {"customer_id": "123"}


def test_blocks_globally_blocked_tool() -> None:
    interceptor = make_interceptor()
    try:
        interceptor.execute(
            agent_name="sales_agent",
            tool_call=ToolCall(name="delete_database", arguments={"name": "prod"}),
            tool_registry={"delete_database": lambda name: {"name": name}},
        )
        assert False, "Expected PolicyViolationError"
    except PolicyViolationError as exc:
        assert "globally blocked" in str(exc)


def test_blocks_dangerous_argument_pattern() -> None:
    interceptor = make_interceptor()
    try:
        interceptor.execute(
            agent_name="sales_agent",
            tool_call=ToolCall(name="send_email", arguments={"body": "please drop table users"}),
            tool_registry={"send_email": lambda body: {"body": body}},
        )
        assert False, "Expected PolicyViolationError"
    except PolicyViolationError as exc:
        assert "blocked pattern" in str(exc)


def test_requires_approval_then_allows_after_approval() -> None:
    interceptor = make_interceptor()
    try:
        interceptor.execute(
            agent_name="ops_agent",
            tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
            tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
        )
        assert False, "Expected ApprovalRequiredError"
    except ApprovalRequiredError as exc:
        approval_id = exc.approval_id

    interceptor.approval_store.approve(approval_id, reviewed_by="reviewer")
    result = interceptor.execute(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
        tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
        approval_id=approval_id,
    )
    assert result == {"service": "orders", "status": "restarted"}


def test_intercept_supports_runtime_context_contract() -> None:
    interceptor = make_interceptor()
    request = InterceptionRequest(
        context=RuntimeContext(
            agent_name="sales_agent",
            tool_name="read_customer",
            arguments={"customer_id": "456"},
            framework="langgraph",
            actor="user-123",
            environment="prod",
            correlation_id="corr-1",
        ),
        tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
    )
    result = interceptor.intercept(request)
    assert result == {"customer_id": "456"}
    events = list(interceptor.audit_logger.events())
    assert len(events) == 2
    assert all(isinstance(event, RuntimeEvent) for event in events)
    assert [event.event_type for event in events] == ["tool_allowed", "tool_executed"]


def test_intercept_blocks_high_sensitivity_context_end_to_end() -> None:
    interceptor = make_sensitivity_interceptor()
    request = InterceptionRequest(
        context=RuntimeContext(
            agent_name="sales_agent",
            tool_name="read_customer",
            arguments={"customer_id": "456"},
            framework="langgraph",
            sensitivity_level="high",
            source="crm",
            data_classification="pii",
        ),
        tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
    )

    try:
        interceptor.intercept(request)
        assert False, "Expected PolicyViolationError"
    except PolicyViolationError as exc:
        assert "Sensitivity level 'high' is blocked by policy" in str(exc)
    events = list(interceptor.audit_logger.events())
    assert len(events) == 1
    assert isinstance(events[0], RuntimeEvent)
    assert events[0].event_type == "tool_blocked"


def test_intercept_emits_approval_required_and_tool_executed_events() -> None:
    interceptor = make_interceptor()

    try:
        interceptor.execute(
            agent_name="ops_agent",
            tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
            tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
        )
        assert False, "Expected ApprovalRequiredError"
    except ApprovalRequiredError as exc:
        approval_id = exc.approval_id

    events = list(interceptor.audit_logger.events())
    assert [event.event_type for event in events] == ["approval_required"]
    assert all(isinstance(event, RuntimeEvent) for event in events)

    interceptor.approval_store.approve(approval_id, reviewed_by="reviewer")
    result = interceptor.execute(
        agent_name="ops_agent",
        tool_call=ToolCall(name="restart_service", arguments={"service": "orders"}),
        tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
        approval_id=approval_id,
    )

    assert result == {"service": "orders", "status": "restarted"}
    assert [event.event_type for event in interceptor.audit_logger.events()] == [
        "approval_required",
        "tool_allowed",
        "tool_executed",
    ]


def test_runtime_events_are_persisted_and_read_back(tmp_path) -> None:
    logger = AuditLogger(log_path=str(tmp_path / "runtime-events.jsonl"))
    policy = PolicyEngine(
        {
            "agents": {
                "sales_agent": {
                    "allowed_tools": ["read_customer"],
                },
            },
        }
    )
    interceptor = AgentInterceptor(policy_engine=policy, audit_logger=logger, approval_store=ApprovalStore())

    result = interceptor.execute(
        agent_name="sales_agent",
        tool_call=ToolCall(name="read_customer", arguments={"customer_id": "123"}),
        tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
    )

    assert result == {"customer_id": "123"}
    persisted = list(logger.persisted_events())
    assert [event.event_type for event in persisted] == ["tool_allowed", "tool_executed"]
    assert all(isinstance(event, RuntimeEvent) for event in persisted)


def test_dry_run_does_not_execute_tool_but_returns_allow_decision() -> None:
    interceptor = make_interceptor()
    executed = {"called": False}

    def read_customer(customer_id: str) -> dict[str, str]:
        executed["called"] = True
        return {"customer_id": customer_id}

    result = interceptor.intercept(
        InterceptionRequest(
            context=RuntimeContext(
                agent_name="sales_agent",
                tool_name="read_customer",
                arguments={"customer_id": "123"},
            ),
            tool_registry={"read_customer": read_customer},
            dry_run=True,
        )
    )

    assert isinstance(result, DryRunResult)
    assert result.would_allow is True
    assert result.would_block is False
    assert result.would_require_approval is False
    assert executed["called"] is False
    assert [event.event_type for event in interceptor.audit_logger.events()] == ["tool_allowed"]


def test_dry_run_returns_approval_requirement_and_emits_event() -> None:
    interceptor = make_interceptor()

    result = interceptor.intercept(
        InterceptionRequest(
            context=RuntimeContext(
                agent_name="ops_agent",
                tool_name="restart_service",
                arguments={"service": "orders"},
            ),
            tool_registry={"restart_service": lambda service: {"service": service}},
            dry_run=True,
        )
    )

    assert isinstance(result, DryRunResult)
    assert result.would_allow is False
    assert result.would_block is False
    assert result.would_require_approval is True
    assert [event.event_type for event in interceptor.audit_logger.events()] == ["approval_required"]
