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
from aisecops_interceptor.integrations.openclaw_adapter import OpenClawToolRunnerAdapter


policy = PolicyEngine.from_yaml_file()
audit = AuditLogger()
approvals = ApprovalStore()
interceptor = AgentInterceptor(policy_engine=policy, audit_logger=audit, approval_store=approvals)
adapter = OpenClawToolRunnerAdapter(interceptor=interceptor)

registry = {
    "get_deployment_status": lambda service: {"service": service, "status": "green"},
    "restart_service": lambda service: {"service": service, "status": "restarted"},
}

safe_payload = {
    "agent_name": "openclaw_agent",
    "tool_name": "get_deployment_status",
    "arguments": {"service": "orders"},
}
print("1) OpenClaw safe call")
print(adapter.run(safe_payload, tool_registry=registry))

risky_payload = {
    "agent_name": "openclaw_agent",
    "tool_name": "restart_service",
    "arguments": {"service": "orders"},
}
print("\n2) OpenClaw approval flow")
try:
    adapter.run(risky_payload, tool_registry=registry)
except ApprovalRequiredError as exc:
    print({"approval_id": exc.approval_id, "message": str(exc)})
    approvals.approve(exc.approval_id, reviewed_by="openclaw-admin")
    print(adapter.run(risky_payload, tool_registry=registry, approval_id=exc.approval_id))
