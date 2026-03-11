from __future__ import annotations

from typing import Any, Callable

from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import ToolCall


class InterceptedToolRegistry:
    def __init__(
        self,
        *,
        agent_name: str,
        interceptor: AgentInterceptor,
        tool_registry: dict[str, Callable[..., Any]],
    ) -> None:
        self.agent_name = agent_name
        self.interceptor = interceptor
        self.tool_registry = tool_registry

    def call(self, tool_name: str, **kwargs: Any) -> Any:
        return self.interceptor.execute(
            agent_name=self.agent_name,
            tool_call=ToolCall(name=tool_name, arguments=kwargs),
            tool_registry=self.tool_registry,
        )
