

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.audit import AuditLogger
from aisecops_interceptor.core.capability_registry import CapabilityRegistry
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.exceptions import ApprovalRequiredError, PolicyViolationError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest
from aisecops_interceptor.core.policy import PolicyEngine
from aisecops_interceptor.llm.models import LLMMessage, LLMRequest, LLMResponse
from aisecops_interceptor.llm.pipeline import GuardedLLMPipeline


class DemoApprovalStore:
    def __init__(self) -> None:
        self._approved: set[str] = set()

    def is_approved(self, approval_id: str | None) -> bool:
        return approval_id is not None and approval_id in self._approved

    def create_request(self, *, agent_name: str, tool_call, reason: str, risk_level: int | None = None):
        approval_id = f"apr-{uuid4().hex[:12]}"
        return SimpleNamespace(
            approval_id=approval_id,
            agent_name=agent_name,
            tool_name=tool_call.name,
            reason=reason,
            risk_level=risk_level,
        )

    def approve(self, approval_id: str) -> None:
        self._approved.add(approval_id)


class FakeLLMClient:
    async def chat(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            content="Call restart_service for payments-api.",
            model="demo-model",
            provider="demo",
        )


def restart_service(service: str) -> dict[str, str]:
    return {"service": service, "status": "restarted"}


async def main() -> None:
    audit_path = Path("audit/agent-demo-runtime-events.jsonl")
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    if audit_path.exists():
        audit_path.unlink()
    audit_logger = AuditLogger(log_path=str(audit_path))
    approval_store = DemoApprovalStore()
    policy_engine = PolicyEngine(
        {
            "rules": [
                {
                    "tool_name": "restart_service",
                    "agent_name": "ops_agent",
                    "action": "require_approval",
                }
            ]
        }
    )
    interceptor = AgentInterceptor(
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        approval_store=approval_store,
        capability_registry=CapabilityRegistry(
            {
                "cap_service_ops": ["restart_service"],
                "cap_customer_read": ["read_customer"],
            }
        ),
    )

    pipeline = GuardedLLMPipeline(client=FakeLLMClient(), event_sink=audit_logger.log)

    print("1) Guarded LLM call")
    llm_context = RuntimeContext(
        agent_name="ops_agent",
        user_id="demo-user",
        session_id="demo-session-1",
        prompt="Help restart the payments service.",
        metadata={"framework": "demo"},
    )
    llm_response = await pipeline.chat(
        LLMRequest(
            messages=[
                LLMMessage(role="system", content="You are a careful operations assistant."),
                LLMMessage(role="user", content="Help restart the payments service."),
            ]
        ),
        context=llm_context,
    )
    print(llm_response.content)

    tool_registry = {"restart_service": restart_service}
    context = RuntimeContext(
        agent_name="ops_agent",
        tool_name="restart_service",
        arguments={"service": "payments-api"},
        framework="demo",
        actor="demo-user",
        environment="dev",
        correlation_id="demo-corr-1",
        allowed_capabilities=["cap_service_ops"],
    )

    print("\n2) Interceptor tool request")
    try:
        result = interceptor.intercept(
            InterceptionRequest(
                context=context,
                tool_registry=tool_registry,
            )
        )
        print(result)
    except ApprovalRequiredError as exc:
        print({
            "approval_required": True,
            "approval_id": exc.approval_id,
            "reason": str(exc),
        })

        approval_store.approve(exc.approval_id)

        print("\n3) Re-run after approval")
        result = interceptor.intercept(
            InterceptionRequest(
                context=context,
                tool_registry=tool_registry,
                approval_id=exc.approval_id,
            )
        )
        print(result)

    print("\n4) Runtime events")
    for event in audit_logger.events():
        if isinstance(event, RuntimeEvent):
            print(
                {
                    "event_type": event.event_type,
                    "decision": event.decision,
                    "tool_name": event.tool_name,
                    "reason": event.reason,
                    "stage": event.stage,
                }
            )
        else:
            print(event)

    print("\n5) Persisted runtime events")
    for event in audit_logger.persisted_events():
        print({"event_type": event.event_type, "stage": event.stage, "tool_name": event.tool_name})

    print("\n6) Filtered persisted runtime events")
    for event in audit_logger.query_persisted_events(stage="tool", tool_name="restart_service"):
        print({"event_type": event.event_type, "stage": event.stage, "tool_name": event.tool_name})

    print("\n7) Capability gate example")
    try:
        interceptor.intercept(
            InterceptionRequest(
                context=RuntimeContext(
                    agent_name="ops_agent",
                    tool_name="restart_service",
                    arguments={"service": "payments-api"},
                    framework="demo",
                    allowed_capabilities=["cap_customer_read"],
                ),
                tool_registry=tool_registry,
            )
        )
    except PolicyViolationError as exc:
        print({"capability_blocked": True, "reason": str(exc)})


if __name__ == "__main__":
    asyncio.run(main())
