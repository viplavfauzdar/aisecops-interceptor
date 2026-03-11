from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import ToolCall


class LangGraphToolAdapter:
    """Lightweight adapter for LangGraph/LangChain-style tool execution."""

    def __init__(self, *, interceptor: AgentInterceptor, agent_name: str) -> None:
        self.interceptor = interceptor
        self.agent_name = agent_name

    def invoke_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None,
        tool_registry: Mapping[str, Any],
        approval_id: str | None = None,
    ) -> Any:
        registry = self._normalize_registry(tool_registry)
        return self.interceptor.execute(
            agent_name=self.agent_name,
            tool_call=ToolCall(name=tool_name, arguments=arguments or {}),
            tool_registry=registry,
            approval_id=approval_id,
        )

    def wrap_tool(self, tool_name: str, tool: Any) -> Callable[[dict[str, Any] | None], Any]:
        registry = {tool_name: self._coerce_tool(tool)}

        def _wrapped(arguments: dict[str, Any] | None = None, *, approval_id: str | None = None) -> Any:
            return self.interceptor.execute(
                agent_name=self.agent_name,
                tool_call=ToolCall(name=tool_name, arguments=arguments or {}),
                tool_registry=registry,
                approval_id=approval_id,
            )

        return _wrapped

    def _normalize_registry(self, tool_registry: Mapping[str, Any]) -> dict[str, Callable[..., Any]]:
        return {name: self._coerce_tool(tool) for name, tool in tool_registry.items()}

    def _coerce_tool(self, tool: Any) -> Callable[..., Any]:
        if callable(tool):
            return tool
        if hasattr(tool, "invoke") and callable(tool.invoke):
            def _invoke_wrapper(**kwargs: Any) -> Any:
                return tool.invoke(kwargs)
            return _invoke_wrapper
        raise TypeError(f"Unsupported tool type: {type(tool)!r}")


class LangGraphMiddleware:
    """Tiny middleware-style hook for graphs that centralize tool calls.

    Usage:
        middleware = LangGraphMiddleware(adapter)
        result = middleware.before_tool_call("tool_name", {"x": 1}, registry)
    """

    def __init__(self, adapter: LangGraphToolAdapter) -> None:
        self.adapter = adapter

    def before_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        tool_registry: Mapping[str, Any],
        *,
        approval_id: str | None = None,
    ) -> Any:
        return self.adapter.invoke_tool(
            tool_name=tool_name,
            arguments=arguments,
            tool_registry=tool_registry,
            approval_id=approval_id,
        )
