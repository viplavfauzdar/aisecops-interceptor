from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aisecops_interceptor.replay.diff import ReplayDiffEngine
from aisecops_interceptor.replay.engine import AuditReplayEngine


class EvidenceExporter:
    def __init__(
        self,
        *,
        replay_engine: AuditReplayEngine | None = None,
        diff_engine: ReplayDiffEngine | None = None,
    ) -> None:
        self.replay_engine = replay_engine or AuditReplayEngine()
        self.diff_engine = diff_engine or ReplayDiffEngine(self.replay_engine)

    def build_package(self, *, audit_file: str | Path, trace_id: str) -> dict[str, Any]:
        timeline = self.replay_engine.replay_trace(audit_file, trace_id)
        summary = self.replay_engine.summarize_timeline(timeline)
        diff = self.diff_engine.diff_timeline(timeline)
        latest_usage = next(
            (entry.runtime_usage for entry in reversed(timeline.entries) if entry.runtime_usage is not None),
            None,
        )
        latest_budget = next(
            (entry.runtime_budget for entry in reversed(timeline.entries) if entry.runtime_budget is not None),
            None,
        )
        return {
            "trace_id": trace_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "agent_identity": {
                "agent_id": summary.agent_id,
                "agent_name": timeline.entries[-1].agent_name if timeline.entries else None,
                "trust_level": summary.agent_trust_level,
                "environment": summary.agent_environment,
            },
            "plan_summary": {
                "plan_id": summary.plan_id,
                "intent": summary.intent,
                "risk_level": summary.risk_level,
                "requested_capabilities": summary.requested_capabilities,
                "step_count": summary.step_count,
            },
            "policy_decision": {
                "final_decision": summary.final_decision,
                "final_reason": summary.final_reason,
            },
            "runtime_budget_usage": {
                "budget_status": summary.budget_status,
                "budget": latest_budget,
                "usage": latest_usage,
                "violations": list(summary.violations),
            },
            "provenance_summary": dict(summary.provenance_trust_summary),
            "replay_timeline_summary": {
                "event_count": summary.event_count,
                "first_seen": summary.first_seen,
                "last_seen": summary.last_seen,
                "schema_versions_observed": list(summary.schema_versions_observed),
            },
            "replay_diff_summary": diff.to_dict(),
            "final_governance_result": diff.governance_result,
        }

    def export(
        self,
        *,
        audit_file: str | Path,
        trace_id: str,
        output_format: str,
        output_path: str | Path | None = None,
    ) -> str:
        package = self.build_package(audit_file=audit_file, trace_id=trace_id)
        if output_format == "json":
            rendered = json.dumps(package, indent=2, sort_keys=True)
        elif output_format == "markdown":
            rendered = self.render_markdown(package)
        else:
            raise ValueError("format must be 'json' or 'markdown'")

        if output_path is not None:
            path = Path(output_path)
            if path.parent != Path("."):
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered + "\n", encoding="utf-8")
        return rendered

    @staticmethod
    def render_markdown(package: dict[str, Any]) -> str:
        identity = package["agent_identity"]
        plan = package["plan_summary"]
        policy = package["policy_decision"]
        runtime = package["runtime_budget_usage"]
        diff = package["replay_diff_summary"]
        lines = [
            "# AISecOps Governance Evidence",
            "",
            f"- Trace ID: `{package['trace_id']}`",
            f"- Generated At: `{package['generated_at']}`",
            f"- Final Governance Result: `{package['final_governance_result']}`",
            "",
            "## Agent Identity",
            "",
            f"- Agent ID: `{identity.get('agent_id')}`",
            f"- Agent Name: `{identity.get('agent_name')}`",
            f"- Trust Level: `{identity.get('trust_level')}`",
            f"- Environment: `{identity.get('environment')}`",
            "",
            "## Plan Summary",
            "",
            f"- Plan ID: `{plan.get('plan_id')}`",
            f"- Intent: `{plan.get('intent')}`",
            f"- Risk Level: `{plan.get('risk_level')}`",
            f"- Requested Capabilities: `{', '.join(plan.get('requested_capabilities') or [])}`",
            "",
            "## Policy Decision",
            "",
            f"- Final Decision: `{policy.get('final_decision')}`",
            f"- Reason: {policy.get('final_reason')}",
            "",
            "## Runtime Budget",
            "",
            f"- Budget Status: `{runtime.get('budget_status')}`",
            f"- Violations: `{', '.join(runtime.get('violations') or [])}`",
            "",
            "## Replay Diff",
            "",
            f"- Governance Result: `{diff.get('governance_result')}`",
            f"- Execution Outcome: `{diff.get('execution_outcome')}`",
            f"- Summary: {diff.get('summary')}",
        ]
        return "\n".join(lines)
