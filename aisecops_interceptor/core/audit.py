from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from aisecops_interceptor.core.event_sink import EventSink, FileEventSink, InMemoryEventSink
from aisecops_interceptor.core.events import RuntimeEvent


DEFAULT_AUDIT_LOG_PATH = "logs/audit.jsonl"


@dataclass(slots=True)
class SinkFailure:
    sink_type: str
    event_type: str
    error_type: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "SinkFailure":
        return cls(
            sink_type=str(data["sink_type"]),
            event_type=str(data["event_type"]),
            error_type=str(data["error_type"]),
            message=str(data["message"]),
        )


class AuditLogger:
    def __init__(
        self,
        log_path: str | None = None,
        sinks: list[EventSink] | None = None,
        sink_failure_log_path: str | None = None,
    ) -> None:
        self.in_memory_sink = InMemoryEventSink()
        self.file_sink = FileEventSink(log_path) if log_path else None
        self.sink_failure_log_path = self._resolve_sink_failure_log_path(
            log_path=log_path,
            sink_failure_log_path=sink_failure_log_path,
        )
        self.sinks: list[EventSink] = [self.in_memory_sink]
        self._sink_failures: list[SinkFailure] = []
        if self.file_sink is not None:
            self.sinks.append(self.file_sink)
        if sinks:
            self.sinks.extend(sinks)

    @staticmethod
    def _resolve_sink_failure_log_path(
        *,
        log_path: str | None,
        sink_failure_log_path: str | None,
    ) -> Path | None:
        if sink_failure_log_path is not None:
            return Path(sink_failure_log_path)
        if log_path is None:
            return None
        return Path(log_path).with_name("sink_failures.jsonl")

    def _persist_sink_failure(self, failure: SinkFailure) -> None:
        if self.sink_failure_log_path is None:
            return
        self.sink_failure_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.sink_failure_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(failure.to_dict()) + "\n")

    def record_sink_failure(self, failure: SinkFailure) -> None:
        self._sink_failures.append(failure)
        self._persist_sink_failure(failure)

    @staticmethod
    def _ensure_trace_id(event: RuntimeEvent) -> None:
        if event.trace_id is not None:
            return
        if event.context is not None:
            event.trace_id = event.context.ensure_trace_id()
            return
        event.trace_id = uuid4().hex

    def log(self, event: RuntimeEvent) -> None:
        self._ensure_trace_id(event)
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception as exc:
                self.record_sink_failure(
                    SinkFailure(
                        sink_type=type(sink).__name__,
                        event_type=event.event_type,
                        error_type=type(exc).__name__,
                        message=str(exc),
                    )
                )
                continue

    def events(self) -> Iterable[RuntimeEvent]:
        return self.in_memory_sink.events()

    def persisted_events(self) -> Iterable[RuntimeEvent]:
        if self.file_sink is None:
            return ()
        return self.file_sink.events()

    def query_persisted_events(
        self,
        *,
        event_type: str | None = None,
        stage: str | None = None,
        agent_name: str | None = None,
        tool_name: str | None = None,
        correlation_id: str | None = None,
        limit: int | None = None,
    ) -> Iterable[RuntimeEvent]:
        if self.file_sink is None:
            return ()
        return self.file_sink.query_events(
            event_type=event_type,
            stage=stage,
            agent_name=agent_name,
            tool_name=tool_name,
            correlation_id=correlation_id,
            limit=limit,
        )

    def sink_failures(self) -> Iterable[SinkFailure]:
        return tuple(self._sink_failures)

    def persisted_sink_failures(self) -> Iterable[SinkFailure]:
        if self.sink_failure_log_path is None or not self.sink_failure_log_path.exists():
            return ()

        failures: list[SinkFailure] = []
        with self.sink_failure_log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                failures.append(SinkFailure.from_dict(json.loads(line)))
        return tuple(failures)

    def query_sink_failures(
        self,
        *,
        sink_type: str | None = None,
        event_type: str | None = None,
        error_type: str | None = None,
        limit: int | None = None,
    ) -> Iterable[SinkFailure]:
        failures = [
            failure for failure in self.persisted_sink_failures()
            if (sink_type is None or failure.sink_type == sink_type)
            and (event_type is None or failure.event_type == event_type)
            and (error_type is None or failure.error_type == error_type)
        ]
        if limit is not None:
            return tuple(failures[:limit])
        return tuple(failures)
