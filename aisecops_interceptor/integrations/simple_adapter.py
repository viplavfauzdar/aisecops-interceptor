
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

from aisecops_interceptor.core.interceptor import AgentInterceptor
from aisecops_interceptor.core.models import InterceptionRequest, RuntimeContext


class BaseRuntimeAdapter(ABC):
    def __init__(self, *, interceptor: AgentInterceptor, framework_name: str, default_agent_name: str) -> None:
        self.interceptor = interceptor
        self.framework_name = framework_name
        self.default_agent_name = default_agent_name

    def build_context(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        agent_name: str | None = None,
        actor: str | None = None,
        environment: str = "dev",
        session_id: str | None = None,
        correlation_id: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> RuntimeContext:
        return RuntimeContext(
            agent_name=agent_name or self.default_agent_name,
            tool_name=tool_name,
            arguments=arguments or {},
            framework=self.framework_name,
            actor=actor,
            environment=environment,
            session_id=session_id,
            correlation_id=correlation_id,
            tags=tags or {},
        )

    def intercept_call(
        self,
        *,
        context: RuntimeContext,
        tool_registry: dict[str, Callable[..., Any]],
        approval_id: str | None = None,
    ) -> Any:
        return self.interceptor.intercept(
            InterceptionRequest(
                context=context,
                tool_registry=tool_registry,
                approval_id=approval_id,
            )
        )

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


class InterceptedToolRegistry(BaseRuntimeAdapter):
    def __init__(
        self,
        *,
        agent_name: str,
        interceptor: AgentInterceptor,
        tool_registry: dict[str, Callable[..., Any]],
        environment: str = "dev",
    ) -> None:
        super().__init__(
            interceptor=interceptor,
            framework_name="simple",
            default_agent_name=agent_name,
        )
        self.tool_registry = tool_registry
        self.environment = environment

    def call(self, tool_name: str, **kwargs: Any) -> Any:
        context = self.build_context(
            tool_name=tool_name,
            arguments=kwargs,
            environment=self.environment,
        )
        return self.intercept_call(context=context, tool_registry=self.tool_registry)

    def run(self, tool_name: str, **kwargs: Any) -> Any:
        return self.call(tool_name, **kwargs)
