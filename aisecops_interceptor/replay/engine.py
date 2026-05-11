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


class AuditReplayEngine:
    def replay_trace(self, audit_file: str | Path, trace_id: str) -> ReplayTimeline:
        path = Path(audit_file)
        if not path.exists():
            raise AuditFileNotFoundError(f"Audit file not found: {path}")

        entries: list[ReplayTimelineEntry] = []
        warnings: list[ReplayWarning] = []
        grouped: dict[str | None, list[ReplayTimelineEntry]] = {}

        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line)
                    event = RuntimeEvent.from_dict(payload)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    warnings.append(
                        ReplayWarning(
                            line_number=line_number,
                            message=f"Skipped malformed audit line: {exc}",
                        )
                    )
                    continue

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
