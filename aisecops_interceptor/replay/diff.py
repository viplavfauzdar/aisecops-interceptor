from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from aisecops_interceptor.core.explanation import explain_governance_decision
from aisecops_interceptor.replay.engine import AuditReplayEngine, ReplayTimeline, ReplayTimelineEntry


@dataclass(slots=True)
class ReplayMismatch:
    type: str
    expected: str | None
    actual: str | None
    severity: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ReplayDiff:
    trace_id: str
    plan_id: str | None
    planned_tool: str | None
    planned_intent: str | None
    planned_capabilities: list[str]
    planned_risk_level: str | None
    policy_decision: str | None
    execution_outcome: str | None
    governance_result: str
    mismatches: list[ReplayMismatch] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["mismatches"] = [mismatch.to_dict() for mismatch in self.mismatches]
        return payload


class ReplayDiffEngine:
    def __init__(self, replay_engine: AuditReplayEngine | None = None) -> None:
        self.replay_engine = replay_engine or AuditReplayEngine()

    def diff_trace(self, audit_file: str | Path, trace_id: str) -> ReplayDiff:
        return self.diff_timeline(self.replay_engine.replay_trace(audit_file, trace_id))

    def diff_timeline(self, timeline: ReplayTimeline) -> ReplayDiff:
        entries = timeline.entries
        plan_entry = next((entry for entry in entries if entry.event_type == "plan"), None)
        decision_entry = self._policy_decision_entry(entries)
        execution_entry = next((entry for entry in entries if entry.event_type == "tool_executed"), None)
        final_entry = entries[-1] if entries else None

        planned_tool = self._planned_tool(plan_entry)
        policy_decision = decision_entry.decision if decision_entry is not None else None
        execution_outcome = "executed" if execution_entry is not None else "not_performed"
        violations = self._runtime_violations(entries)
        mismatches = self._mismatches(
            planned_tool=planned_tool,
            policy_decision=policy_decision,
            execution_outcome=execution_outcome,
            final_entry=final_entry,
            violations=violations,
        )
        governance_result = self._governance_result(
            policy_decision=policy_decision,
            execution_outcome=execution_outcome,
            mismatches=mismatches,
        )
        summary = self._summary(
            planned_tool=planned_tool,
            policy_decision=policy_decision,
            execution_outcome=execution_outcome,
            governance_result=governance_result,
            decision_entry=decision_entry,
            violations=violations,
        )

        return ReplayDiff(
            trace_id=timeline.trace_id,
            plan_id=plan_entry.plan_id if plan_entry is not None else None,
            planned_tool=planned_tool,
            planned_intent=plan_entry.plan_intent if plan_entry is not None else None,
            planned_capabilities=list(plan_entry.requested_capabilities) if plan_entry is not None else [],
            planned_risk_level=plan_entry.plan_risk_level if plan_entry is not None else None,
            policy_decision=policy_decision,
            execution_outcome=execution_outcome,
            governance_result=governance_result,
            mismatches=mismatches,
            violations=violations,
            summary=summary,
        )

    @staticmethod
    def _policy_decision_entry(entries: list[ReplayTimelineEntry]) -> ReplayTimelineEntry | None:
        return next(
            (
                entry
                for entry in reversed(entries)
                if entry.event_type in {"decision", "mcp_policy_decision"}
                and entry.decision in {"allowed", "blocked", "require_approval"}
            ),
            None,
        )

    @staticmethod
    def _planned_tool(entry: ReplayTimelineEntry | None) -> str | None:
        if entry is None:
            return None
        if entry.tool_name:
            return entry.tool_name
        if entry.plan_steps:
            return str(entry.plan_steps[0].get("tool_name") or "") or None
        return None

    @staticmethod
    def _runtime_violations(entries: list[ReplayTimelineEntry]) -> list[str]:
        violations: list[str] = []
        for entry in entries:
            for violation in entry.runtime_violations:
                if violation not in violations:
                    violations.append(violation)
        return violations

    @staticmethod
    def _mismatches(
        *,
        planned_tool: str | None,
        policy_decision: str | None,
        execution_outcome: str,
        final_entry: ReplayTimelineEntry | None,
        violations: list[str],
    ) -> list[ReplayMismatch]:
        mismatches: list[ReplayMismatch] = []
        if policy_decision == "blocked" and execution_outcome == "executed":
            mismatches.append(
                ReplayMismatch(
                    type="blocked_execution_occurred",
                    expected="not_performed",
                    actual="executed",
                    severity="critical",
                    reason="Policy blocked the action, but execution occurred.",
                )
            )
        if policy_decision == "require_approval" and execution_outcome == "executed":
            approved = final_entry is not None and final_entry.decision == "allowed"
            if not approved:
                mismatches.append(
                    ReplayMismatch(
                        type="approval_execution_without_allowed_final_state",
                        expected="approval_before_execution",
                        actual="executed",
                        severity="high",
                        reason="Execution occurred without an allowed final governance state.",
                    )
                )
        if planned_tool and final_entry and final_entry.tool_name and final_entry.tool_name != planned_tool:
            mismatches.append(
                ReplayMismatch(
                    type="tool_mismatch",
                    expected=planned_tool,
                    actual=final_entry.tool_name,
                    severity="medium",
                    reason="The final event tool differs from the planned tool.",
                )
            )
        for violation in violations:
            mismatches.append(
                ReplayMismatch(
                    type="runtime_budget_violation",
                    expected="within_budget",
                    actual=violation,
                    severity="high",
                    reason=f"Runtime budget violation observed: {violation}",
                )
            )
        return mismatches

    @staticmethod
    def _governance_result(
        *,
        policy_decision: str | None,
        execution_outcome: str,
        mismatches: list[ReplayMismatch],
    ) -> str:
        if any(mismatch.severity == "critical" for mismatch in mismatches):
            return "violation"
        if policy_decision == "blocked" and execution_outcome == "not_performed":
            return "blocked"
        if policy_decision == "require_approval" and execution_outcome == "not_performed":
            return "enforced"
        if policy_decision == "allowed" and execution_outcome == "executed":
            return "matched"
        if mismatches:
            return "review"
        return "observed"

    @staticmethod
    def _summary(
        *,
        planned_tool: str | None,
        policy_decision: str | None,
        execution_outcome: str,
        governance_result: str,
        decision_entry: ReplayTimelineEntry | None,
        violations: list[str],
    ) -> str:
        explanation = explain_governance_decision(
            tool_name=planned_tool,
            decision=policy_decision,
            reason=decision_entry.reason if decision_entry is not None else None,
            matched_rule=None,
            budget_violations=violations,
        )
        return (
            f"{explanation} Governance result is {governance_result}; "
            f"execution outcome is {execution_outcome}."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare planned, policy, and execution replay evidence.")
    parser.add_argument("--trace-id", required=True, help="Trace ID to diff")
    parser.add_argument("--audit-log", required=True, help="Replay-compatible audit JSONL path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        diff = ReplayDiffEngine().diff_trace(args.audit_log, args.trace_id)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(diff.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
