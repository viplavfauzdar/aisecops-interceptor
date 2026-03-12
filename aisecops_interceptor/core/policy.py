from __future__ import annotations

from typing import Any

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.models import PolicyDecision, ToolCall
from aisecops_interceptor.policy.loader import PolicyLoader
from aisecops_interceptor.policy.rule_engine import RuleEngine
from aisecops_interceptor.policy.rules import Rule
from aisecops_interceptor.policy.schema import parse_policy_bundle


class PolicyEngine:
    def __init__(self, config: dict[str, Any], rules: list[Rule] | None = None) -> None:
        bundle = parse_policy_bundle(config)
        resolved_rules = rules if rules is not None else bundle.rules
        self.config = bundle.config
        self.rule_engine = RuleEngine(resolved_rules)

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        bundle = PolicyLoader.from_yaml(path)
        return cls(bundle.config, rules=bundle.rules)

    @classmethod
    def from_yaml_file(cls, path: str) -> "PolicyEngine":
        return cls.from_yaml(path)

    def evaluate(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None = None,
    ) -> PolicyDecision:
        rule_decision = self.rule_engine.evaluate(
            agent_name=agent_name,
            tool_call=tool_call,
            context=context,
        )
        if rule_decision is not None:
            return rule_decision

        classification_config = self.config.get("data_classification", {})
        blocked_sensitivity_levels = {
            str(level).lower() for level in classification_config.get("blocked_sensitivity_levels", [])
        }
        if context and context.sensitivity_level and context.sensitivity_level.lower() in blocked_sensitivity_levels:
            return PolicyDecision(
                allowed=False,
                reason=f"Sensitivity level '{context.sensitivity_level}' is blocked by policy",
                matched_rule="data_classification.blocked_sensitivity_levels",
                risk_level="high",
            )

        blocked_tools = set(self.config.get("blocked_tools", []))
        if tool_call.name in blocked_tools:
            return PolicyDecision(
                allowed=False,
                reason=f"Tool '{tool_call.name}' is globally blocked",
                matched_rule="blocked_tools",
                risk_level="high",
            )

        dangerous_patterns = self.config.get("dangerous_argument_patterns", [])
        for pattern in dangerous_patterns:
            needle = str(pattern).lower()
            if self._arguments_contain(tool_call.arguments, needle):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Arguments matched blocked pattern '{needle}'",
                    matched_rule="dangerous_argument_patterns",
                    risk_level="high",
                )

        per_agent = self.config.get("agents", {}).get(agent_name, {})
        allowed_tools = per_agent.get("allowed_tools")
        if allowed_tools is not None and tool_call.name not in set(allowed_tools):
            return PolicyDecision(
                allowed=False,
                reason=f"Agent '{agent_name}' is not allowed to use tool '{tool_call.name}'",
                matched_rule=f"agents.{agent_name}.allowed_tools",
                risk_level="medium",
            )

        require_approval = set(per_agent.get("approval_required_tools", []))
        if tool_call.name in require_approval:
            return PolicyDecision(
                allowed=False,
                reason=f"Tool '{tool_call.name}' requires human approval",
                matched_rule=f"agents.{agent_name}.approval_required_tools",
                risk_level="high",
                requires_approval=True,
            )

        monitored_tools = set(self.config.get("monitored_tools", []))
        if tool_call.name in monitored_tools:
            return PolicyDecision(
                allowed=True,
                reason=f"Tool '{tool_call.name}' allowed with audit monitoring",
                matched_rule="monitored_tools",
                risk_level="medium",
            )

        return PolicyDecision(allowed=True, reason="Allowed by policy", risk_level="low")

    def _arguments_contain(self, data: Any, needle: str) -> bool:
        if isinstance(data, dict):
            return any(self._arguments_contain(v, needle) for v in data.values())
        if isinstance(data, list):
            return any(self._arguments_contain(v, needle) for v in data)
        return needle in str(data).lower()
