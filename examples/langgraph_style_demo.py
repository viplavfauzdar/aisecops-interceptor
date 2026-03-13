import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.exceptions import ApprovalRequiredError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.integrations.langgraph_adapter import LangGraphMiddleware, LangGraphToolAdapter


policy = PolicyEngine.from_yaml_file()
audit = AuditLogger()
approvals = ApprovalStore()
interceptor = AgentInterceptor(policy_engine=policy, audit_logger=audit, approval_store=approvals)
adapter = LangGraphToolAdapter(interceptor=interceptor, agent_name="ops_agent")
middleware = LangGraphMiddleware(adapter)

registry = {
    "get_deployment_status": lambda service: {"service": service, "status": "green"},
    "restart_service": lambda service: {"service": service, "status": "restarted"},
}

print("1) Safe tool call")
print(
    middleware.before_tool_call(
        "get_deployment_status",
        {"service": "payments"},
        registry,
    )
)

print("\n2) Approval-required tool call")
try:
    middleware.before_tool_call("restart_service", {"service": "payments"}, registry)
except ApprovalRequiredError as exc:
    print({"approval_required": True, "approval_id": exc.approval_id, "message": str(exc)})
    approvals.approve(exc.approval_id, reviewed_by="human.reviewer", note="Approved for incident mitigation")
    print("3) Re-run after approval")
    print(
        middleware.before_tool_call(
            "restart_service",
            {"service": "payments"},
            registry,
            approval_id=exc.approval_id,
        )
    )

print("\n4) Audit log entries")
for event in audit.events():
    print(event)
