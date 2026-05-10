from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aisecops_interceptor.core.models import CapabilityDefinition
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
    capabilities: dict[str, CapabilityDefinition] = field(default_factory=dict)


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

    tool_name = data.get("tool_name", data.get("tool"))
    if tool_name is not None and str(tool_name).strip() == "":
        raise PolicyBundleValidationError("Rule field 'tool_name' must be non-empty when provided")

    action = data.get("action", data.get("effect"))
    if action is None:
        raise PolicyBundleValidationError("Rule field 'action' is required")
    normalized_action = str(action)
    if normalized_action == "deny":
        normalized_action = "block"

    raw_provenance_trust = data.get("provenance_trust", [])
    if raw_provenance_trust is None:
        raw_provenance_trust = []
    if not isinstance(raw_provenance_trust, list):
        raise PolicyBundleValidationError("Rule field 'provenance_trust' must be a list")

    raw_provenance_source_type = data.get("provenance_source_type", [])
    if raw_provenance_source_type is None:
        raw_provenance_source_type = []
    if not isinstance(raw_provenance_source_type, list):
        raise PolicyBundleValidationError("Rule field 'provenance_source_type' must be a list")

    if (
        tool_name is None
        and data.get("agent_name") is None
        and data.get("sensitivity_level") is None
        and not raw_provenance_trust
        and not raw_provenance_source_type
    ):
        raise PolicyBundleValidationError("Rule must define at least one matching condition")

    try:
        return Rule(
            tool_name=str(tool_name) if tool_name is not None else None,
            action=normalized_action,
            agent_name=str(data["agent_name"]) if data.get("agent_name") is not None else None,
            sensitivity_level=(
                str(data["sensitivity_level"])
                if data.get("sensitivity_level") is not None
                else None
            ),
            provenance_trust=tuple(str(value) for value in raw_provenance_trust),
            provenance_source_type=tuple(str(value) for value in raw_provenance_source_type),
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

    capabilities: dict[str, CapabilityDefinition] = {}
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

        description = definition.get("description")
        if description is not None and not isinstance(description, str):
            raise CapabilityBundleValidationError(
                f"Capability '{capability_name}' field 'description' must be a string"
            )

        risk = definition.get("risk")
        if risk is not None:
            if not isinstance(risk, str):
                raise CapabilityBundleValidationError(
                    f"Capability '{capability_name}' field 'risk' must be a string"
                )
            normalized_risk = risk.lower()
            if normalized_risk not in {"low", "medium", "high"}:
                raise CapabilityBundleValidationError(
                    f"Capability '{capability_name}' field 'risk' must be one of: low, medium, high"
                )
            risk = normalized_risk

        capabilities[str(capability_name)] = CapabilityDefinition(
            tools=tuple(tools),
            description=description,
            risk=risk,
        )

    return CapabilityBundle(capabilities=capabilities)
