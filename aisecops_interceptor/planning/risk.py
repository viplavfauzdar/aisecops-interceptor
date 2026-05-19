from __future__ import annotations

from typing import Literal

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


def risk_for_tool(tool_name: str | None) -> RiskLevel:
    if not tool_name:
        return "low"
    normalized = tool_name.lower()
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
    levels.extend(step.risk_level for step in plan.steps)
    return _max_risk(levels)
