from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.exceptions import ApprovalRequiredError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.integrations.openclaw_adapter import OpenClawToolRunnerAdapter


def make_adapter() -> tuple[OpenClawToolRunnerAdapter, ApprovalStore]:
    policy = PolicyEngine(
        {
            "agents": {
                "openclaw_agent": {
                    "allowed_tools": ["get_deployment_status", "restart_service"],
                    "approval_required_tools": ["restart_service"],
                }
            }
        }
    )
    approvals = ApprovalStore()
    interceptor = AgentInterceptor(policy_engine=policy, audit_logger=AuditLogger(), approval_store=approvals)
    return OpenClawToolRunnerAdapter(interceptor=interceptor), approvals


def test_openclaw_adapter_safe_call() -> None:
    adapter, _ = make_adapter()
    result = adapter.run(
        {"agent_name": "openclaw_agent", "tool_name": "get_deployment_status", "arguments": {"service": "payments"}},
        tool_registry={"get_deployment_status": lambda service: {"service": service, "status": "green"}},
    )
    assert result == {"service": "payments", "status": "green"}


def test_openclaw_adapter_approval_flow() -> None:
    adapter, approvals = make_adapter()
    payload = {"agent_name": "openclaw_agent", "tool_name": "restart_service", "arguments": {"service": "payments"}}
    try:
        adapter.run(payload, tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}})
        assert False, "Expected ApprovalRequiredError"
    except ApprovalRequiredError as exc:
        approvals.approve(exc.approval_id, reviewed_by="reviewer")
        result = adapter.run(
            payload,
            tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
            approval_id=exc.approval_id,
        )
        assert result == {"service": "payments", "status": "restarted"}
