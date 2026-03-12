from dataclasses import dataclass, field
from typing import List


@dataclass(slots=True)
class GuardFinding:
    rule: str
    severity: str
    message: str


@dataclass(slots=True)
class GuardResult:
    allowed: bool
    findings: List[GuardFinding] = field(default_factory=list)
