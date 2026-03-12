from enum import Enum
from dataclasses import dataclass


class DecisionType(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(slots=True)
class DecisionResult:
    decision: DecisionType
    reason: str | None = None
