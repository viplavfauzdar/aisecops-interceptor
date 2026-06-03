"""MCP policy proxy foundation for AISecOps Interceptor."""

from aisecops_interceptor.mcp.models import MCPDecision, MCPInvocation

__all__ = ["MCPDecision", "MCPInvocation", "MCPPolicyProxy"]


def __getattr__(name: str):
    if name == "MCPPolicyProxy":
        from aisecops_interceptor.mcp.proxy import MCPPolicyProxy

        return MCPPolicyProxy
    raise AttributeError(name)
