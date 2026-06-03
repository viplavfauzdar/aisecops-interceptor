from __future__ import annotations


def explain_governance_decision(
    *,
    tool_name: str | None = None,
    capability: str | None = None,
    decision: str | None = None,
    reason: str | None = None,
    matched_rule: str | None = None,
    budget_violations: list[str] | None = None,
) -> str:
    if budget_violations:
        return (
            "Runtime budget blocked execution because "
            f"{budget_violations[0]} was exceeded."
        )

    tool = tool_name or "the requested tool"
    if decision == "blocked":
        if capability:
            return f"Policy blocked {tool} because {capability} is not allowed for this agent."
        if reason:
            return f"Policy blocked {tool}: {reason}"
        return f"Policy blocked {tool}."

    if decision == "require_approval":
        if capability:
            return f"Execution required approval because {capability} is marked high risk."
        if reason:
            return f"Execution required approval: {reason}"
        return "Execution required approval before the tool could run."

    if decision == "allowed":
        if matched_rule:
            return f"Policy allowed {tool} under {matched_rule}."
        return f"Policy allowed {tool}."

    return reason or "Governance decision was evaluated."
