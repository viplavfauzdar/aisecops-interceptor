from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


RuleAction = Literal["allow", "block", "require_approval"]
VALID_RULE_ACTIONS = frozenset({"allow", "block", "require_approval"})


@dataclass(slots=True)
class Rule:
    tool_name: str | None
    action: RuleAction
    agent_name: str | None = None
    sensitivity_level: str | None = None
    provenance_trust: tuple[str, ...] = field(default_factory=tuple)
    provenance_source_type: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.tool_name is not None and self.tool_name.strip() == "":
            raise ValueError("Rule field 'tool_name' must be non-empty when provided")
        if self.action not in VALID_RULE_ACTIONS:
            raise ValueError("Rule field 'action' must be allow, block, or require_approval")
        if (
            self.tool_name is None
            and self.agent_name is None
            and self.sensitivity_level is None
            and not self.provenance_trust
            and not self.provenance_source_type
        ):
            raise ValueError("Rule must define at least one matching condition")
        self.provenance_trust = tuple(value.lower() for value in self.provenance_trust)
        self.provenance_source_type = tuple(value.lower() for value in self.provenance_source_type)
