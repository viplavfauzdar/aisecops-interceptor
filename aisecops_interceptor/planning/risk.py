from __future__ import annotations

from typing import Literal

from aisecops_interceptor.planning.capabilities import canonical_capability_for_tool
from aisecops_interceptor.planning.models import ExecutionPlan

RiskLevel = Literal["low", "medium", "high", "critical"]

_RISK_ORDER: dict[RiskLevel, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_MEDIUM_TERMS = ("email", "send", "notify", "notification", "message")
_HIGH_TERMS = ("write", "update", "delete", "remove", "create", "modify")
_CRITICAL_TERMS = (
    "shell",
    "exec",
    "infra",
    "restart",
    "stop_service",
    "trade",
    "payment",
    "pay",
    "deploy",
)

_CAPABILITY_RISKS: dict[str, RiskLevel] = {
    "customer.read": "low",
    "email.send": "medium",
    "filesystem.write": "high",
    "filesystem.delete": "high",
    "infra.restart": "critical",
    "system.shell": "critical",
    "trade.execute": "critical",
    "payment.send": "critical",
}


def risk_for_tool(tool_name: str | None) -> RiskLevel:
    if not tool_name:
        return "low"
    canonical_capability = canonical_capability_for_tool(tool_name)
    if canonical_capability is not None:
        return risk_for_capability(canonical_capability)
    normalized = tool_name.lower()
    if any(term in normalized for term in _CRITICAL_TERMS):
        return "critical"
    if any(term in normalized for term in _HIGH_TERMS):
        return "high"
    if any(term in normalized for term in _MEDIUM_TERMS):
        return "medium"
    return "low"


def risk_for_capability(capability: str | None) -> RiskLevel:
    if not capability:
        return "low"
    normalized = capability.lower()
    if normalized in _CAPABILITY_RISKS:
        return _CAPABILITY_RISKS[normalized]
    if any(term in normalized for term in _CRITICAL_TERMS):
        return "critical"
    if any(term in normalized for term in _HIGH_TERMS):
        return "high"
    if any(term in normalized for term in _MEDIUM_TERMS):
        return "medium"
    return "low"


def _max_risk(levels: list[RiskLevel]) -> RiskLevel:
    return max(levels, key=lambda level: _RISK_ORDER[level], default="low")


def score_plan(plan: ExecutionPlan) -> RiskLevel:
    levels = [risk_for_tool(plan.requested_tool), plan.risk_level]
    levels.extend(risk_for_capability(capability) for capability in plan.requested_capabilities)
    levels.extend(step.risk_level for step in plan.steps)
    levels.extend(risk_for_capability(step.capability) for step in plan.steps)
    return _max_risk(levels)
