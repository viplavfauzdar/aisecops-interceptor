from __future__ import annotations

from aisecops_interceptor.core.models import CapabilityDefinition

KNOWN_MCP_CAPABILITIES = {
    "filesystem.read": "filesystem.read",
    "filesystem.write": "filesystem.write",
    "email.send": "email.send",
    "web.fetch": "web.fetch",
}


def capability_for_mcp_tool(tool_name: str) -> tuple[str, bool]:
    capability = KNOWN_MCP_CAPABILITIES.get(tool_name)
    if capability is not None:
        return capability, False
    return tool_name, True


def mcp_capability_mapping(tool_name: str) -> dict[str, CapabilityDefinition]:
    capability, _unknown = capability_for_mcp_tool(tool_name)
    return {
        capability: CapabilityDefinition(
            tools=(tool_name,),
            description=f"MCP capability for {tool_name}",
            risk="medium",
        )
    }
