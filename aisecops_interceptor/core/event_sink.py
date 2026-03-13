from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Protocol

import httpx

from aisecops_interceptor.core.events import RuntimeEvent


class EventSink(Protocol):
    def emit(self, event: RuntimeEvent) -> None:
        ...


class InMemoryEventSink:
    def __init__(self) -> None:
        self._events: list[RuntimeEvent] = []

    def emit(self, event: RuntimeEvent) -> None:
        self._events.append(event)

    def events(self) -> Iterable[RuntimeEvent]:
        return tuple(self._events)


class FileEventSink:
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def emit(self, event: RuntimeEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def events(self) -> Iterable[RuntimeEvent]:
        if not self.path.exists():
            return ()

        events: list[RuntimeEvent] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(RuntimeEvent.from_dict(json.loads(line)))
        return tuple(events)

    def query_events(
        self,
        *,
        event_type: str | None = None,
        stage: str | None = None,
        agent_name: str | None = None,
        tool_name: str | None = None,
        correlation_id: str | None = None,
        limit: int | None = None,
    ) -> Iterable[RuntimeEvent]:
        filtered = [
            event for event in self.events()
            if (event_type is None or event.event_type == event_type)
            and (stage is None or event.stage == stage)
            and (agent_name is None or event.agent_name == agent_name)
            and (tool_name is None or event.tool_name == tool_name)
            and (correlation_id is None or event.correlation_id == correlation_id)
        ]
        if limit is not None:
            return tuple(filtered[:limit])
        return tuple(filtered)


class WebhookEventSink:
    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self.url = url
        self.timeout = timeout

    def emit(self, event: RuntimeEvent) -> None:
        response = httpx.post(
            self.url,
            json=event.to_dict(),
            timeout=self.timeout,
        )
        response.raise_for_status()
