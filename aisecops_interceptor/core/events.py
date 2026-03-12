from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class AuditEvent:
    timestamp: datetime
    agent: Optional[str]
    user: Optional[str]
    action: str
    decision: str
    tool: Optional[str] = None
    risk: Optional[str] = None
