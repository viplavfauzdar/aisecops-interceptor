from __future__ import annotations

from typing import Any

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.cost import CostEstimator
from aisecops_interceptor.core.models import AgentIdentity, PolicyDecision, RuntimeBudget, RuntimeUsage, ToolCall
from aisecops_interceptor.policy.loader import PolicyLoader
from aisecops_interceptor.policy.rule_engine import RuleEngine
from aisecops_interceptor.policy.rules import Rule
from aisecops_interceptor.policy.schema import parse_policy_bundle

DEFAULT_HIGH_RISK_TOOLS = (
    "restart_service",
    "shell_exec",
    "delete_user",
    "export_data",
)


class PolicyEngine:
    def __init__(self, config: dict[str, Any], rules: list[Rule] | None = None) -> None:
        bundle = parse_policy_bundle(config)
        resolved_rules = rules if rules is not None else bundle.rules
        self.config = bundle.config
        self.rule_engine = RuleEngine(resolved_rules)
        configured_high_risk_tools = tuple(str(tool) for tool in self.config.get("high_risk_tools", []))
        high_risk_mode = str(self.config.get("high_risk_tools_mode", "extend")).lower()
        if high_risk_mode == "override":
            self.high_risk_tools = configured_high_risk_tools
        else:
            self.high_risk_tools = tuple(
                dict.fromkeys(DEFAULT_HIGH_RISK_TOOLS + configured_high_risk_tools)
            )
        self.cost_estimator = CostEstimator()

    @classmethod
    def from_yaml(cls, path: str | None = None) -> "PolicyEngine":
        bundle = PolicyLoader.from_yaml(path)
        return cls(bundle.config, rules=bundle.rules)

    @classmethod
    def from_yaml_file(cls, path: str | None = None) -> "PolicyEngine":
        return cls.from_yaml(path)

    def evaluate(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None = None,
    ) -> PolicyDecision:
        budget_decision = self._evaluate_runtime_budget(
            agent_name=agent_name,
            tool_call=tool_call,
            context=context,
        )
        if budget_decision is not None:
            return budget_decision

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

        if tool_call.name in set(self.high_risk_tools):
            return PolicyDecision(
                allowed=False,
                reason=f"Tool '{tool_call.name}' is in the default high-risk preset and requires human approval",
                matched_rule="high_risk_tools",
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

    def runtime_budget_for_agent(self, agent_name: str | None) -> RuntimeBudget:
        global_limits = self.config.get("agent_limits", {})
        agent_limits = self.config.get("agents", {}).get(agent_name or "", {})
        merged = {
            "max_tool_calls": 20,
            "max_depth": 5,
            "max_runtime_seconds": 60,
            "max_cost_usd": 2.00,
        }
        if isinstance(global_limits, dict):
            merged.update(self._budget_fields(global_limits))
        if isinstance(agent_limits, dict):
            merged.update(self._budget_fields(agent_limits))
        return RuntimeBudget(
            max_tool_calls=int(merged["max_tool_calls"]),
            max_depth=int(merged["max_depth"]),
            max_runtime_seconds=float(merged["max_runtime_seconds"]),
            max_cost_usd=float(merged["max_cost_usd"]),
        )

    def agent_identity_for(self, agent_name: str | None) -> AgentIdentity | None:
        if agent_name is None:
            return None
        agent_config = self.config.get("agents", {}).get(agent_name, {})
        if not isinstance(agent_config, dict):
            return None

        identity_fields = {
            "agent_id",
            "trust_level",
            "environment",
            "allowed_capabilities",
            "max_tool_calls",
            "max_depth",
            "max_runtime_seconds",
            "max_cost_usd",
        }
        if not any(field in agent_config for field in identity_fields):
            return None

        return AgentIdentity(
            agent_id=str(agent_config.get("agent_id") or agent_name),
            agent_name=agent_name,
            trust_level=str(agent_config.get("trust_level") or "unspecified"),
            environment=str(agent_config.get("environment") or "dev"),
            allowed_capabilities=[str(item) for item in agent_config.get("allowed_capabilities", [])],
            max_tool_calls=(
                int(agent_config["max_tool_calls"]) if agent_config.get("max_tool_calls") is not None else None
            ),
            max_depth=int(agent_config["max_depth"]) if agent_config.get("max_depth") is not None else None,
            max_runtime_seconds=(
                float(agent_config["max_runtime_seconds"])
                if agent_config.get("max_runtime_seconds") is not None
                else None
            ),
            max_cost_usd=(
                float(agent_config["max_cost_usd"]) if agent_config.get("max_cost_usd") is not None else None
            ),
        )

    def enrich_context_with_agent_identity(self, context: RuntimeContext) -> RuntimeContext:
        identity = self.agent_identity_for(context.agent_name)
        if identity is None:
            return context

        context.agent_id = context.agent_id or identity.agent_id
        context.agent_trust_level = context.agent_trust_level or identity.trust_level
        context.agent_environment = context.agent_environment or identity.environment
        context.environment = context.environment or identity.environment
        if context.allowed_capabilities is None and identity.allowed_capabilities:
            context.allowed_capabilities = list(identity.allowed_capabilities)
        context.metadata.setdefault("agent_identity", identity.to_dict())
        if identity.runtime_budget_overrides() and context.runtime_budget is None:
            base_budget = self.runtime_budget_for_agent(context.agent_name)
            context.runtime_budget = RuntimeBudget(
                max_tool_calls=base_budget.max_tool_calls,
                max_depth=base_budget.max_depth,
                max_runtime_seconds=base_budget.max_runtime_seconds,
                max_cost_usd=base_budget.max_cost_usd,
            )
        return context

    def runtime_usage_for_context(
        self,
        *,
        context: RuntimeContext | None,
        tool_call: ToolCall,
    ) -> RuntimeUsage:
        usage = context.runtime_usage if context is not None and context.runtime_usage is not None else RuntimeUsage()
        estimated_cost = usage.estimated_cost_usd
        if estimated_cost <= 0:
            estimated_cost = self.cost_estimator.estimate_tool_cost_usd(tool_call.name)
        return RuntimeUsage(
            tool_calls_used=max(0, int(usage.tool_calls_used)),
            depth_used=max(0, int(usage.depth_used)),
            runtime_seconds=max(0, float(usage.runtime_seconds)),
            estimated_cost_usd=max(0, float(estimated_cost)),
        )

    def runtime_budget_status(
        self,
        *,
        agent_name: str | None,
        tool_call: ToolCall,
        context: RuntimeContext | None,
    ) -> tuple[RuntimeBudget, RuntimeUsage, list[str]]:
        budget = context.runtime_budget if context is not None and context.runtime_budget is not None else self.runtime_budget_for_agent(agent_name)
        usage = self.runtime_usage_for_context(context=context, tool_call=tool_call)
        violations: list[str] = []
        if usage.tool_calls_used >= budget.max_tool_calls:
            violations.append("tool_call_budget_exceeded")
        if usage.depth_used >= budget.max_depth:
            violations.append("depth_limit_exceeded")
        if usage.runtime_seconds >= budget.max_runtime_seconds:
            violations.append("runtime_limit_exceeded")
        if usage.estimated_cost_usd >= budget.max_cost_usd:
            violations.append("cost_limit_exceeded")
        return budget, usage, violations

    def _evaluate_runtime_budget(
        self,
        *,
        agent_name: str,
        tool_call: ToolCall,
        context: RuntimeContext | None,
    ) -> PolicyDecision | None:
        budget, usage, violations = self.runtime_budget_status(
            agent_name=agent_name,
            tool_call=tool_call,
            context=context,
        )
        if context is not None:
            context.runtime_budget = budget
            context.runtime_usage = usage
        if not violations:
            return None
        return PolicyDecision(
            allowed=False,
            reason=violations[0],
            matched_rule="agent_limits",
            risk_level="medium",
        )

    @staticmethod
    def _budget_fields(data: dict[str, Any]) -> dict[str, Any]:
        return {
            key: data[key]
            for key in ("max_tool_calls", "max_depth", "max_runtime_seconds", "max_cost_usd")
            if key in data
        }

    def _arguments_contain(self, data: Any, needle: str) -> bool:
        if isinstance(data, dict):
            return any(self._arguments_contain(v, needle) for v in data.values())
        if isinstance(data, list):
            return any(self._arguments_contain(v, needle) for v in data)
        return needle in str(data).lower()
