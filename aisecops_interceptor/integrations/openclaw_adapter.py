from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.integrations.simple_adapter import BaseRuntimeAdapter


class OpenClawToolRunnerAdapter(BaseRuntimeAdapter):
    """Minimal OpenClaw-style tool runner adapter.

    Assumes an OpenClaw plugin or tool runner emits a request payload like:
    {
      "agent_name": "ops_agent",
      "tool_name": "restart_service",
      "arguments": {"service": "payments"}
    }
    """

    def __init__(self, *, interceptor: AgentInterceptor, default_agent_name: str = "openclaw_agent", environment: str = "dev") -> None:
        super().__init__(
            interceptor=interceptor,
            framework_name="openclaw",
            default_agent_name=default_agent_name,
        )
        self.environment = environment

    def run(
        self,
        payload: Mapping[str, Any],
        *,
        tool_registry: Mapping[str, Any],
        approval_id: str | None = None,
    ) -> Any:
        agent_name = str(payload.get("agent_name") or self.default_agent_name)
        tool_name = str(payload["tool_name"])
        arguments = dict(payload.get("arguments") or {})
        registry = {name: tool for name, tool in tool_registry.items()}
        context = self.build_context(
            tool_name=tool_name,
            arguments=arguments,
            agent_name=agent_name,
            actor=str(payload.get("actor")) if payload.get("actor") is not None else None,
            environment=str(payload.get("environment") or self.environment),
            session_id=str(payload.get("session_id")) if payload.get("session_id") is not None else None,
            correlation_id=str(payload.get("correlation_id")) if payload.get("correlation_id") is not None else None,
        )
        return self.intercept_call(
            context=context,
            tool_registry=registry,
            approval_id=approval_id,
        )
