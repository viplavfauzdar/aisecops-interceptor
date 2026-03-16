from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aisecops_interceptor.policy.rules import Rule


class PolicyBundleValidationError(ValueError):
    """Raised when a YAML policy bundle is invalid."""


class CapabilityBundleValidationError(ValueError):
    """Raised when a YAML capability bundle is invalid."""


@dataclass(slots=True)
class PolicyBundle:
    config: dict[str, Any] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)


@dataclass(slots=True)
class CapabilityBundle:
    capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)


def parse_policy_bundle(data: Any) -> PolicyBundle:
    if data is None:
        return PolicyBundle(config={}, rules=[])
    if not isinstance(data, dict):
        raise PolicyBundleValidationError("Policy bundle must be a mapping")

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyBundleValidationError("'rules' must be a list")

    rules = [parse_rule(item) for item in raw_rules]
    return PolicyBundle(config=dict(data), rules=rules)


def parse_rule(data: Any) -> Rule:
    if not isinstance(data, dict):
        raise PolicyBundleValidationError("Each rule must be a mapping")

    tool_name = data.get("tool_name")
    if tool_name is None or str(tool_name).strip() == "":
        raise PolicyBundleValidationError("Rule field 'tool_name' is required")

    action = data.get("action")
    if action is None:
        raise PolicyBundleValidationError("Rule field 'action' is required")

    try:
        return Rule(
            tool_name=str(tool_name),
            action=str(action),
            agent_name=str(data["agent_name"]) if data.get("agent_name") is not None else None,
            sensitivity_level=(
                str(data["sensitivity_level"])
                if data.get("sensitivity_level") is not None
                else None
            ),
        )
    except ValueError as exc:
        raise PolicyBundleValidationError(str(exc)) from exc


def parse_capability_bundle(data: Any) -> CapabilityBundle:
    if data is None:
        return CapabilityBundle(capabilities={})
    if not isinstance(data, dict):
        raise CapabilityBundleValidationError("Capability bundle must be a mapping")

    raw_capabilities = data.get("capabilities", {})
    if not isinstance(raw_capabilities, dict):
        raise CapabilityBundleValidationError("'capabilities' must be a mapping")

    capabilities: dict[str, tuple[str, ...]] = {}
    for capability_name, definition in raw_capabilities.items():
        if str(capability_name).strip() == "":
            raise CapabilityBundleValidationError("Capability names must be non-empty strings")
        if not isinstance(definition, dict):
            raise CapabilityBundleValidationError(
                f"Capability '{capability_name}' must be a mapping"
            )

        raw_tools = definition.get("tools")
        if not isinstance(raw_tools, list):
            raise CapabilityBundleValidationError(
                f"Capability '{capability_name}' field 'tools' must be a list"
            )

        tools: list[str] = []
        for tool_name in raw_tools:
            if str(tool_name).strip() == "":
                raise CapabilityBundleValidationError(
                    f"Capability '{capability_name}' tools must contain non-empty strings"
                )
            tools.append(str(tool_name))

        capabilities[str(capability_name)] = tuple(tools)

    return CapabilityBundle(capabilities=capabilities)
