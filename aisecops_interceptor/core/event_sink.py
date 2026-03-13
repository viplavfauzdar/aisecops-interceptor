from __future__ import annotations

import hmac
import hashlib
import json
import time
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
    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        retry_count: int = 2,
        backoff_delay: float = 0.05,
        secret_key: str | None = None,
        header_name: str = "X-AISecOps-Signature",
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.retry_count = retry_count
        self.backoff_delay = backoff_delay
        self.secret_key = secret_key
        self.header_name = header_name

    @staticmethod
    def _serialize_event(event: RuntimeEvent) -> str:
        return json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))

    def _headers_for_event(self, payload: str) -> dict[str, str] | None:
        if self.secret_key is None:
            return None
        signature = hmac.new(
            self.secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {self.header_name: signature}

    def emit(self, event: RuntimeEvent) -> None:
        payload = event.to_dict()
        serialized_payload = self._serialize_event(event)
        headers = self._headers_for_event(serialized_payload)
        last_error: httpx.HTTPError | None = None
        for attempt in range(self.retry_count + 1):
            try:
                response = httpx.post(
                    self.url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                return
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == self.retry_count:
                    raise
                time.sleep(self.backoff_delay)

        if last_error is not None:
            raise last_error
