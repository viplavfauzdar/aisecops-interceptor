from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


RuleAction = Literal["allow", "block", "require_approval"]
VALID_RULE_ACTIONS = frozenset({"allow", "block", "require_approval"})


@dataclass(slots=True)
class Rule:
    tool_name: str
    action: RuleAction
    agent_name: str | None = None
    sensitivity_level: str | None = None

    def __post_init__(self) -> None:
        if self.tool_name.strip() == "":
            raise ValueError("Rule field 'tool_name' is required")
        if self.action not in VALID_RULE_ACTIONS:
            raise ValueError("Rule field 'action' must be allow, block, or require_approval")
