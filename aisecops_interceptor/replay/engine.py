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

    @classmethod
    def from_event(cls, event: RuntimeEvent) -> "ReplayTimelineEntry":
        return cls(
            timestamp=event.timestamp,
            event_type=event.event_type,
            schema_version=event.schema_version,
            event_id=event.event_id,
            decision_stage=event.decision_stage,
            agent_name=event.agent_name,
            tool_name=event.tool_name,
            decision=event.decision,
            reason=event.reason,
            provenance=list(event.provenance or ()),
            execution_plan_id=event.execution_plan_id,
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
    first_seen: str | None = None
    last_seen: str | None = None


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

        for entry in timeline.entries:
            version = entry.schema_version or "legacy"
            if version not in seen_versions:
                seen_versions.add(version)
                schema_versions.append(version)
            for item in entry.provenance:
                trust_summary[item.trust_level] = trust_summary.get(item.trust_level, 0) + 1

        return ReplaySummary(
            trace_id=timeline.trace_id,
            event_count=len(timeline.entries),
            final_decision=final_entry.decision if final_entry is not None else None,
            tool_name=final_entry.tool_name if final_entry is not None else None,
            final_reason=final_entry.reason if final_entry is not None else None,
            provenance_trust_summary=trust_summary,
            schema_versions_observed=schema_versions,
            first_seen=timeline.entries[0].timestamp if timeline.entries else None,
            last_seen=timeline.entries[-1].timestamp if timeline.entries else None,
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
