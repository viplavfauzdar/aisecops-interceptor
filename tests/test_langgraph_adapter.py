from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.exceptions import ApprovalRequiredError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.integrations.langgraph_adapter import LangGraphMiddleware, LangGraphToolAdapter


def make_adapter() -> tuple[LangGraphToolAdapter, ApprovalStore]:
    policy = PolicyEngine(
        {
            "agents": {
                "ops_agent": {
                    "allowed_tools": ["get_deployment_status", "restart_service"],
                    "approval_required_tools": ["restart_service"],
                }
            }
        }
    )
    approvals = ApprovalStore()
    interceptor = AgentInterceptor(policy_engine=policy, audit_logger=AuditLogger(), approval_store=approvals)
    return LangGraphToolAdapter(interceptor=interceptor, agent_name="ops_agent"), approvals


def test_langgraph_adapter_allows_safe_tool() -> None:
    adapter, _ = make_adapter()
    result = adapter.invoke_tool(
        tool_name="get_deployment_status",
        arguments={"service": "orders"},
        tool_registry={"get_deployment_status": lambda service: {"service": service, "status": "green"}},
    )
    assert result == {"service": "orders", "status": "green"}


def test_langgraph_middleware_supports_approval_flow() -> None:
    adapter, approvals = make_adapter()
    middleware = LangGraphMiddleware(adapter)
    try:
        middleware.before_tool_call(
            "restart_service",
            {"service": "orders"},
            {"restart_service": lambda service: {"service": service, "status": "restarted"}},
        )
        assert False, "Expected ApprovalRequiredError"
    except ApprovalRequiredError as exc:
        approvals.approve(exc.approval_id, reviewed_by="ops-admin")
        result = middleware.before_tool_call(
            "restart_service",
            {"service": "orders"},
            {"restart_service": lambda service: {"service": service, "status": "restarted"}},
            approval_id=exc.approval_id,
        )
        assert result == {"service": "orders", "status": "restarted"}
