from aisecops_interceptor.core.approval import ApprovalStore
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest, PolicyDecision, ToolCall
from aisecops_interceptor.core.policy import PolicyEngine


def make_capability_interceptor() -> AgentInterceptor:
    policy = PolicyEngine(
        {
            "agents": {
                "ops_agent": {
                    "allowed_tools": ["restart_service"],
                },
                "sales_agent": {
                    "allowed_tools": ["read_customer"],
                },
            },
        }
    )
    capability_registry = CapabilityRegistry(
        {
            "cap_service_ops": ["restart_service"],
            "cap_customer_read": ["read_customer"],
        }
    )
    return AgentInterceptor(
        policy_engine=policy,
        audit_logger=AuditLogger(),
        approval_store=ApprovalStore(),
        capability_registry=capability_registry,
    )


def test_allowed_capability_permits_tool_execution() -> None:
    interceptor = make_capability_interceptor()
    result = interceptor.intercept(
        InterceptionRequest(
            context=RuntimeContext(
                agent_name="sales_agent",
                tool_name="read_customer",
                arguments={"customer_id": "123"},
                allowed_capabilities=["cap_customer_read"],
            ),
            tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
        )
    )

    assert result == {"customer_id": "123"}


def test_missing_capability_blocks_tool_execution() -> None:
    interceptor = make_capability_interceptor()

    try:
        interceptor.intercept(
            InterceptionRequest(
                context=RuntimeContext(
                    agent_name="ops_agent",
                    tool_name="restart_service",
                    arguments={"service": "orders"},
                    allowed_capabilities=["cap_customer_read"],
                ),
                tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
            )
        )
        assert False, "Expected capability gate to block execution"
    except PolicyViolationError as exc:
        assert "requires one of the granted capabilities" in str(exc)

    events = list(interceptor.audit_logger.events())
    assert len(events) == 1
    assert events[0].event_type == "tool_blocked"
    assert events[0].matched_rule == "capability_gate"


def test_capability_block_happens_before_policy_evaluation() -> None:
    class FailOnEvaluatePolicyEngine:
        def evaluate(self, *, agent_name: str, tool_call: ToolCall, context: RuntimeContext | None = None):
            raise AssertionError("Policy evaluation should not run when capability gate blocks")

    interceptor = AgentInterceptor(
        policy_engine=FailOnEvaluatePolicyEngine(),
        audit_logger=AuditLogger(),
        approval_store=ApprovalStore(),
        capability_registry=CapabilityRegistry({"cap_service_ops": ["restart_service"]}),
    )

    try:
        interceptor.intercept(
            InterceptionRequest(
                context=RuntimeContext(
                    agent_name="ops_agent",
                    tool_name="restart_service",
                    arguments={"service": "orders"},
                    allowed_capabilities=["cap_customer_read"],
                ),
                tool_registry={"restart_service": lambda service: {"service": service, "status": "restarted"}},
            )
        )
        assert False, "Expected capability gate to block execution"
    except PolicyViolationError as exc:
        assert "requires one of the granted capabilities" in str(exc)


def test_backward_compatibility_without_capability_list() -> None:
    interceptor = make_capability_interceptor()
    result = interceptor.intercept(
        InterceptionRequest(
            context=RuntimeContext(
                agent_name="sales_agent",
                tool_name="read_customer",
                arguments={"customer_id": "123"},
                allowed_capabilities=None,
            ),
            tool_registry={"read_customer": lambda customer_id: {"customer_id": customer_id}},
        )
    )

    assert result == {"customer_id": "123"}
