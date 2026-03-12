from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from aisecops_interceptor.core.events import RuntimeEvent


class AuditLogger:
    def __init__(self, log_path: str | None = None) -> None:
        self._events: list[RuntimeEvent] = []
        self.log_path = Path(log_path) if log_path else None

    def log(self, event: RuntimeEvent) -> None:
        self._events.append(event)
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

    def events(self) -> Iterable[RuntimeEvent]:
        return tuple(self._events)

    def persisted_events(self) -> Iterable[RuntimeEvent]:
        if self.log_path is None or not self.log_path.exists():
            return ()

        events: list[RuntimeEvent] = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(RuntimeEvent.from_dict(json.loads(line)))
        return tuple(events)
