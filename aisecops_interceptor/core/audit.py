from __future__ import annotations

import json
from dataclasses import asdict
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
                f.write(json.dumps(asdict(event)) + "\n")

    def events(self) -> Iterable[RuntimeEvent]:
        return tuple(self._events)
