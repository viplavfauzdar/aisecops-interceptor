from __future__ import annotations

from dataclasses import asdict

from aisecops_interceptor.core.models import CapabilityDefinition
from aisecops_interceptor.policy.capabilities import load_capability_bundle


class CapabilityRegistry:
    def __init__(
        self,
        mapping: dict[str, list[str] | set[str] | tuple[str, ...] | CapabilityDefinition] | None = None,
    ) -> None:
        self._capabilities: dict[str, CapabilityDefinition] = {}
        for capability, value in (mapping or {}).items():
            if isinstance(value, CapabilityDefinition):
                self._capabilities[capability] = value
                continue
            self._capabilities[capability] = CapabilityDefinition(tools=tuple(value))

    @classmethod
    def from_yaml(cls, path: str | None = None) -> "CapabilityRegistry":
        bundle = load_capability_bundle(path)
        return cls(bundle.capabilities)

    @classmethod
    def from_yaml(cls, path: str | None = None) -> "CapabilityRegistry":
        bundle = load_capability_bundle(path)
        return cls(bundle.capabilities)

    def required_capabilities_for_tool(self, tool_name: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                capability
                for capability, definition in self._capabilities.items()
                if tool_name in definition.tools
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

    def metadata_for_capability(self, capability_name: str) -> CapabilityDefinition | None:
        return self._capabilities.get(capability_name)

    def metadata_for_tool(self, tool_name: str) -> dict[str, CapabilityDefinition]:
        return {
            capability: definition
            for capability, definition in self._capabilities.items()
            if tool_name in definition.tools
        }

    def serialized_metadata_for_tool(self, tool_name: str) -> dict[str, dict[str, str | tuple[str, ...] | None]]:
        return {
            capability: asdict(definition)
            for capability, definition in self.metadata_for_tool(tool_name).items()
        }
