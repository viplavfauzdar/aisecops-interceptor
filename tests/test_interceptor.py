from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import ToolCall
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
