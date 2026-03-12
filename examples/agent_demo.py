

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace
from uuid import uuid4

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.exceptions import ApprovalRequiredError
from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest
from aisecops_interceptor.llm.models import LLMMessage, LLMRequest, LLMResponse
from aisecops_interceptor.llm.pipeline import GuardedLLMPipeline


@dataclass(slots=True)
class DemoPolicyDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    risk_level: int | None = None
    matched_rule: str | None = None


class DemoPolicyEngine:
    def evaluate(self, *, agent_name: str, tool_call) -> DemoPolicyDecision:
        if tool_call.name == "restart_service":
            return DemoPolicyDecision(
                allowed=False,
                requires_approval=True,
                reason="restart_service requires approval",
                risk_level=3,
                matched_rule="approval.restart_service",
            )

        return DemoPolicyDecision(
            allowed=True,
            requires_approval=False,
            reason="allowed by demo policy",
            risk_level=1,
            matched_rule="allow.default",
        )


class DemoAuditLogger:
    def __init__(self) -> None:
        self.events = []

    def log(self, event) -> None:
        self.events.append(event)


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
    audit_logger = DemoAuditLogger()
    approval_store = DemoApprovalStore()
    interceptor = AgentInterceptor(
        policy_engine=DemoPolicyEngine(),
        audit_logger=audit_logger,
        approval_store=approval_store,
    )

    pipeline = GuardedLLMPipeline(client=FakeLLMClient())

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

    print("\n4) Audit events")
    for event in audit_logger.events:
        print(event)


if __name__ == "__main__":
    asyncio.run(main())
