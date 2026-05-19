from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

RiskLevel = Literal["low", "medium", "high", "critical"]

PLAN_SCHEMA_VERSION = "0.8.0"


class PlanStep(BaseModel):
    schema_version: str = PLAN_SCHEMA_VERSION
    step_id: str = Field(default_factory=lambda: uuid4().hex)
    intent: str
    tool_name: str | None = None
    capability: str | None = None
    target: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = "low"
    order: int = 1


class ExecutionPlan(BaseModel):
    schema_version: str = PLAN_SCHEMA_VERSION
    plan_id: str = Field(default_factory=lambda: uuid4().hex)
    trace_id: str | None = None
    agent_name: str | None = None
    user_input: str | None = None
    model_output: str | None = None
    intent: str
    requested_tool: str | None = None
    requested_capabilities: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = "low"
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    steps: list[PlanStep] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def step_count(self) -> int:
        return len(self.steps)
