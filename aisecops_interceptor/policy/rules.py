from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


RuleAction = Literal["allow", "block", "require_approval"]


@dataclass(slots=True)
class Rule:
    tool_name: str
    action: RuleAction
    agent_name: str | None = None
    sensitivity_level: str | None = None
