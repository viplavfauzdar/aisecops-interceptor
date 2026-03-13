from __future__ import annotations


class CapabilityRegistry:
    def __init__(self, mapping: dict[str, list[str] | set[str] | tuple[str, ...]] | None = None) -> None:
        self._mapping = {
            capability: set(tool_names)
            for capability, tool_names in (mapping or {}).items()
        }

    def required_capabilities_for_tool(self, tool_name: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                capability
                for capability, tool_names in self._mapping.items()
                if tool_name in tool_names
            )
        )

    def is_tool_allowed(self, tool_name: str, granted_capabilities: list[str] | None) -> bool:
        if granted_capabilities is None:
            return True

        granted = set(granted_capabilities)
        return any(
            capability in granted
            for capability in self.required_capabilities_for_tool(tool_name)
        )
