from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.core.models import InstructionProvenance


class ReplayError(Exception):
    """Base error for audit replay failures."""


class AuditFileNotFoundError(ReplayError):
    """Raised when the audit file does not exist."""


class TraceNotFoundError(ReplayError):
    """Raised when a trace_id has no matching events."""


@dataclass(slots=True)
class ReplayWarning:
    line_number: int
    message: str


@dataclass(slots=True)
class ReplayTimelineEntry:
    timestamp: str
    event_type: str
    schema_version: str | None
    event_id: str | None
    decision_stage: str | None
    agent_name: str | None
    tool_name: str | None
    decision: str
    reason: str | None
    provenance: list[InstructionProvenance]
    execution_plan_id: str | None
    agent_id: str | None = None
    agent_trust_level: str | None = None
    agent_environment: str | None = None
    plan_id: str | None = None
    plan_intent: str | None = None
    plan_risk_level: str | None = None
    requested_capabilities: list[str] = field(default_factory=list)
    plan_steps: list[dict] = field(default_factory=list)
    model_output: str | None = None
    user_input: str | None = None
    protocol: str | None = None
    client_id: str | None = None
    server_name: str | None = None
    capability: str | None = None
    budget_status: str | None = None
    runtime_budget: dict | None = None
    runtime_usage: dict | None = None
    runtime_violations: list[str] = field(default_factory=list)
    tool_calls_used: int | None = None
    tool_calls_remaining: int | None = None
    depth_used: int | None = None
    runtime_seconds: float | None = None
    estimated_cost_usd: float | None = None

    @classmethod
    def from_event(cls, event: RuntimeEvent) -> "ReplayTimelineEntry":
        return cls(
            timestamp=event.timestamp,
            event_type=event.event_type,
            schema_version=event.schema_version,
            event_id=event.event_id,
            decision_stage=event.decision_stage,
            agent_name=event.agent_name,
            agent_id=event.agent_id,
            agent_trust_level=event.agent_trust_level,
            agent_environment=event.agent_environment,
            tool_name=event.tool_name,
            decision=event.decision,
            reason=event.reason,
            provenance=list(event.provenance or ()),
            execution_plan_id=event.execution_plan_id,
            plan_id=event.plan_id,
            plan_intent=event.plan_intent,
            plan_risk_level=event.plan_risk_level,
            requested_capabilities=list(event.requested_capabilities or ()),
            plan_steps=list(event.plan_steps or ()),
            model_output=event.model_output,
            user_input=event.user_input,
            protocol=event.protocol,
            client_id=event.client_id,
            server_name=event.server_name,
            capability=event.capability,
            budget_status=event.budget_status,
            runtime_budget=dict(event.runtime_budget) if event.runtime_budget is not None else None,
            runtime_usage=dict(event.runtime_usage) if event.runtime_usage is not None else None,
            runtime_violations=list(event.runtime_violations or ()),
            tool_calls_used=event.tool_calls_used,
            tool_calls_remaining=event.tool_calls_remaining,
            depth_used=event.depth_used,
            runtime_seconds=event.runtime_seconds,
            estimated_cost_usd=event.estimated_cost_usd,
        )


@dataclass(slots=True)
class ReplayTimeline:
    trace_id: str
    entries: list[ReplayTimelineEntry]
    grouped_entries: dict[str | None, list[ReplayTimelineEntry]]
    warnings: list[ReplayWarning] = field(default_factory=list)


@dataclass(slots=True)
class ReplaySummary:
    trace_id: str
    event_count: int
    final_decision: str | None
    tool_name: str | None
    final_reason: str | None
    provenance_trust_summary: dict[str, int]
    schema_versions_observed: list[str]
    agent_id: str | None = None
    agent_trust_level: str | None = None
    agent_environment: str | None = None
    plan_id: str | None = None
    intent: str | None = None
    risk_level: str | None = None
    requested_capabilities: list[str] | None = None
    step_count: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    protocol: str | None = None
    client_id: str | None = None
    server_name: str | None = None
    capability: str | None = None
    budget_status: str | None = None
    usage_summary: dict | None = None
    violations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReplayTraceResult:
    trace_id: str
    event_count: int
    execution_plan_ids: list[str]
    timeline: list[ReplayTimelineEntry]
    schema_versions_observed: list[str]
    provenance_summary: dict[str, int]
    final_decision: str | None
    final_reason: str | None
    agent_id: str | None = None
    agent_trust_level: str | None = None
    agent_environment: str | None = None
    plan_id: str | None = None
    intent: str | None = None
    risk_level: str | None = None
    requested_capabilities: list[str] | None = None
    step_count: int | None = None
    protocol: str | None = None
    client_id: str | None = None
    server_name: str | None = None
    capability: str | None = None
    budget_status: str | None = None
    usage_summary: dict | None = None
    violations: list[str] = field(default_factory=list)


class AuditReplayEngine:
    @staticmethod
    def _load_events(audit_file: str | Path) -> tuple[list[RuntimeEvent], list[ReplayWarning]]:
        path = Path(audit_file)
        if not path.exists():
            raise AuditFileNotFoundError(f"Audit file not found: {path}")

        events: list[RuntimeEvent] = []
        warnings: list[ReplayWarning] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line)
                    events.append(RuntimeEvent.from_dict(payload))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    warnings.append(
                        ReplayWarning(
                            line_number=line_number,
                            message=f"Skipped malformed audit line: {exc}",
                        )
                    )
                    continue
        return events, warnings

    def replay_trace(self, audit_file: str | Path, trace_id: str) -> ReplayTimeline:
        events, warnings = self._load_events(audit_file)
        entries: list[ReplayTimelineEntry] = []
        grouped: dict[str | None, list[ReplayTimelineEntry]] = {}

        for event in events:
            if event.trace_id != trace_id:
                continue

            entry = ReplayTimelineEntry.from_event(event)
            entries.append(entry)
            grouped.setdefault(entry.execution_plan_id, []).append(entry)

        if not entries:
            raise TraceNotFoundError(f"No audit events found for trace_id '{trace_id}'")

        return ReplayTimeline(
            trace_id=trace_id,
            entries=entries,
            grouped_entries=grouped,
            warnings=warnings,
        )

    @staticmethod
    def summarize_timeline(timeline: ReplayTimeline) -> ReplaySummary:
        final_entry = timeline.entries[-1] if timeline.entries else None
        trust_summary: dict[str, int] = {}
        schema_versions: list[str] = []
        seen_versions: set[str] = set()
        plan_entry = next((entry for entry in timeline.entries if entry.plan_id is not None), None)
        identity_entry = next(
            (
                entry
                for entry in reversed(timeline.entries)
                if entry.agent_id is not None
                or entry.agent_trust_level is not None
                or entry.agent_environment is not None
            ),
            None,
        )
        protocol_entry = next((entry for entry in reversed(timeline.entries) if entry.protocol is not None), None)
        usage_entry = next((entry for entry in reversed(timeline.entries) if entry.runtime_usage is not None), None)
        violations: list[str] = []

        for entry in timeline.entries:
            version = entry.schema_version or "legacy"
            if version not in seen_versions:
                seen_versions.add(version)
                schema_versions.append(version)
            for item in entry.provenance:
                trust_summary[item.trust_level] = trust_summary.get(item.trust_level, 0) + 1
            for violation in entry.runtime_violations:
                if violation not in violations:
                    violations.append(violation)

        return ReplaySummary(
            trace_id=timeline.trace_id,
            event_count=len(timeline.entries),
            final_decision=final_entry.decision if final_entry is not None else None,
            tool_name=final_entry.tool_name if final_entry is not None else None,
            agent_id=identity_entry.agent_id if identity_entry is not None else None,
            agent_trust_level=identity_entry.agent_trust_level if identity_entry is not None else None,
            agent_environment=identity_entry.agent_environment if identity_entry is not None else None,
            final_reason=final_entry.reason if final_entry is not None else None,
            provenance_trust_summary=trust_summary,
            schema_versions_observed=schema_versions,
            plan_id=plan_entry.plan_id if plan_entry is not None else None,
            intent=plan_entry.plan_intent if plan_entry is not None else None,
            risk_level=plan_entry.plan_risk_level if plan_entry is not None else None,
            requested_capabilities=(
                list(plan_entry.requested_capabilities) if plan_entry is not None else None
            ),
            step_count=len(plan_entry.plan_steps) if plan_entry is not None else None,
            first_seen=timeline.entries[0].timestamp if timeline.entries else None,
            last_seen=timeline.entries[-1].timestamp if timeline.entries else None,
            protocol=protocol_entry.protocol if protocol_entry is not None else None,
            client_id=protocol_entry.client_id if protocol_entry is not None else None,
            server_name=protocol_entry.server_name if protocol_entry is not None else None,
            capability=protocol_entry.capability if protocol_entry is not None else None,
            budget_status=(
                "violated"
                if violations
                else (usage_entry.budget_status if usage_entry is not None else None)
            ),
            usage_summary=dict(usage_entry.runtime_usage) if usage_entry is not None and usage_entry.runtime_usage is not None else None,
            violations=violations,
        )

    @staticmethod
    def build_trace_result(timeline: ReplayTimeline) -> ReplayTraceResult:
        summary = AuditReplayEngine.summarize_timeline(timeline)
        execution_plan_ids: list[str] = []
        seen_plan_ids: set[str] = set()

        for entry in timeline.entries:
            if entry.execution_plan_id is None or entry.execution_plan_id in seen_plan_ids:
                continue
            seen_plan_ids.add(entry.execution_plan_id)
            execution_plan_ids.append(entry.execution_plan_id)

        return ReplayTraceResult(
            trace_id=timeline.trace_id,
            event_count=len(timeline.entries),
            execution_plan_ids=execution_plan_ids,
            timeline=list(timeline.entries),
            schema_versions_observed=summary.schema_versions_observed,
            provenance_summary=summary.provenance_trust_summary,
            final_decision=summary.final_decision,
            final_reason=summary.final_reason,
            agent_id=summary.agent_id,
            agent_trust_level=summary.agent_trust_level,
            agent_environment=summary.agent_environment,
            plan_id=summary.plan_id,
            intent=summary.intent,
            risk_level=summary.risk_level,
            requested_capabilities=summary.requested_capabilities,
            step_count=summary.step_count,
            protocol=summary.protocol,
            client_id=summary.client_id,
            server_name=summary.server_name,
            capability=summary.capability,
            budget_status=summary.budget_status,
            usage_summary=summary.usage_summary,
            violations=summary.violations,
        )

    def list_traces(
        self,
        audit_file: str | Path,
        *,
        limit: int = 50,
        decision: str | None = None,
        tool_name: str | None = None,
        provenance_trust: str | None = None,
    ) -> list[ReplaySummary]:
        try:
            events, _warnings = self._load_events(audit_file)
        except AuditFileNotFoundError:
            return []

        traces: dict[str, list[RuntimeEvent]] = {}
        for event in events:
            if event.trace_id is None:
                continue
            traces.setdefault(event.trace_id, []).append(event)

        summaries: list[ReplaySummary] = []
        for trace_id, trace_events in traces.items():
            grouped_entries: dict[str | None, list[ReplayTimelineEntry]] = {}
            entries = [ReplayTimelineEntry.from_event(event) for event in trace_events]
            for entry in entries:
                grouped_entries.setdefault(entry.execution_plan_id, []).append(entry)
            summary = self.summarize_timeline(
                ReplayTimeline(
                    trace_id=trace_id,
                    entries=entries,
                    grouped_entries=grouped_entries,
                )
            )
            summaries.append(summary)

        filtered = [
            summary
            for summary in summaries
            if (decision is None or summary.final_decision == decision)
            and (tool_name is None or summary.tool_name == tool_name)
            and (
                provenance_trust is None
                or provenance_trust in summary.provenance_trust_summary
            )
        ]
        filtered.sort(key=lambda item: item.last_seen or "", reverse=True)
        return filtered[:limit]
