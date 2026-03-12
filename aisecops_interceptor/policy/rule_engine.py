from __future__ import annotations

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.models import PolicyDecision, ToolCall
from aisecops_interceptor.policy.rules import Rule


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = list(rules)

    def evaluate(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None = None,
    ) -> PolicyDecision | None:
        for index, rule in enumerate(self.rules):
            if not self._matches(rule=rule, agent_name=agent_name, tool_call=tool_call, context=context):
                continue
            return self._decision_for(rule, index=index)
        return None

    def _matches(
        self,
        *,
        rule: Rule,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None,
    ) -> bool:
        if rule.tool_name != tool_call.name:
            return False
        if rule.agent_name is not None and rule.agent_name != agent_name:
            return False
        if rule.sensitivity_level is not None:
            if context is None or context.sensitivity_level is None:
                return False
            if context.sensitivity_level.lower() != rule.sensitivity_level.lower():
                return False
        return True

    def _decision_for(self, rule: Rule, *, index: int) -> PolicyDecision:
        matched_rule = f"rules[{index}]"
        if rule.action == "allow":
            return PolicyDecision(
                allowed=True,
                reason=f"Rule allowed tool '{rule.tool_name}'",
                matched_rule=matched_rule,
                risk_level="low",
            )
        if rule.action == "block":
            return PolicyDecision(
                allowed=False,
                reason=f"Rule blocked tool '{rule.tool_name}'",
                matched_rule=matched_rule,
                risk_level="high",
            )
        return PolicyDecision(
            allowed=False,
            reason=f"Rule requires approval for tool '{rule.tool_name}'",
            matched_rule=matched_rule,
            risk_level="high",
            requires_approval=True,
        )
