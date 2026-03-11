from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import ToolCall


class OpenClawToolRunnerAdapter:
    """Minimal OpenClaw-style tool runner adapter.

    Assumes an OpenClaw plugin or tool runner emits a request payload like:
    {
      "agent_name": "ops_agent",
      "tool_name": "restart_service",
      "arguments": {"service": "payments"}
    }
    """

    def __init__(self, *, interceptor: AgentInterceptor, default_agent_name: str = "openclaw_agent") -> None:
        self.interceptor = interceptor
        self.default_agent_name = default_agent_name

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
        return self.interceptor.execute(
            agent_name=agent_name,
            tool_call=ToolCall(name=tool_name, arguments=arguments),
            tool_registry=registry,
            approval_id=approval_id,
        )
