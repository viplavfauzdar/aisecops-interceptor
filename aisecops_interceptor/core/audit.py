from __future__ import annotations

from typing import Iterable

from aisecops_interceptor.core.event_sink import FileEventSink, InMemoryEventSink
from aisecops_interceptor.core.events import RuntimeEvent


class AuditLogger:
    def __init__(
        self,
        log_path: str | None = None,
        sinks: list[InMemoryEventSink | FileEventSink] | None = None,
    ) -> None:
        self.in_memory_sink = InMemoryEventSink()
        self.file_sink = FileEventSink(log_path) if log_path else None
        self.sinks = [self.in_memory_sink]
        if self.file_sink is not None:
            self.sinks.append(self.file_sink)
        if sinks:
            self.sinks.extend(sinks)

    def log(self, event: RuntimeEvent) -> None:
        for sink in self.sinks:
            sink.emit(event)

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
