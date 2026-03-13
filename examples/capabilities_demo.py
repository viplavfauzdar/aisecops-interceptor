from __future__ import annotations

from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest
from aisecops_interceptor.core.policy import PolicyEngine


def restart_service(service: str) -> dict[str, str]:
    return {"service": service, "status": "restarted"}


def main() -> None:
    interceptor = AgentInterceptor(
        policy_engine=PolicyEngine({"agents": {"ops_agent": {"allowed_tools": ["restart_service"]}}}),
        audit_logger=AuditLogger(),
        approval_store=ApprovalStore(),
        capability_registry=CapabilityRegistry.from_yaml("policies/capabilities.yaml"),
    )
    tool_registry = {"restart_service": restart_service}

    allowed_request = InterceptionRequest(
        context=RuntimeContext(
            agent_name="ops_agent",
            tool_name="restart_service",
            arguments={"service": "payments-api"},
            allowed_capabilities=["cap_service_ops"],
        ),
        tool_registry=tool_registry,
    )
    print("allowed:", interceptor.intercept(allowed_request))

    blocked_request = InterceptionRequest(
        context=RuntimeContext(
            agent_name="ops_agent",
            tool_name="restart_service",
            arguments={"service": "payments-api"},
            allowed_capabilities=["cap_customer_read"],
        ),
        tool_registry=tool_registry,
    )
    try:
        interceptor.intercept(blocked_request)
    except PolicyViolationError as exc:
        print("blocked:", str(exc))


if __name__ == "__main__":
    main()
