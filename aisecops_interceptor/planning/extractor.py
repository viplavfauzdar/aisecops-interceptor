from __future__ import annotations

import json
import re
from typing import Any

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.planning.models import ExecutionPlan, PlanStep
from aisecops_interceptor.planning.risk import risk_for_tool, score_plan

_TOOL_RE = re.compile(r"\b(?:tool|call|use|run|execute)\s+([a-zA-Z_][\w.-]*)", re.IGNORECASE)
_INTENT_RE = re.compile(r"\bintent\s*[:=]\s*([a-zA-Z_][\w.-]*)", re.IGNORECASE)
_TARGET_RE = re.compile(r"\b(?:target|service|customer|account)\s*[:=]\s*([a-zA-Z0-9_.:-]+)", re.IGNORECASE)
_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


class PlanExtractor:
    def extract(self, context: RuntimeContext, *, plan_id: str | None = None) -> ExecutionPlan:
        context.ensure_trace_id()
        explicit = self._from_context(context, plan_id=plan_id)
        if explicit.requested_tool:
            return explicit
        return self._from_text(context, plan_id=plan_id)

    def _from_context(self, context: RuntimeContext, *, plan_id: str | None = None) -> ExecutionPlan:
        tool_name = context.tool_name
        intent = self._intent_from_tool(tool_name)
        requested_capabilities = self._requested_capabilities(context, tool_name)
        targets = self._targets_from_arguments(context.arguments)
        risk_level = risk_for_tool(tool_name)
        step = PlanStep(
            intent=intent,
            tool_name=tool_name,
            capability=requested_capabilities[0] if requested_capabilities else None,
            target=targets[0] if targets else None,
            parameters=dict(context.arguments),
            risk_level=risk_level,
            order=1,
        )
        plan_kwargs = {"plan_id": plan_id} if plan_id is not None else {}
        plan = ExecutionPlan(
            **plan_kwargs,
            trace_id=context.trace_id,
            agent_name=context.agent_name,
            user_input=context.prompt,
            model_output=context.model_output,
            intent=intent,
            requested_tool=tool_name,
            requested_capabilities=requested_capabilities,
            targets=targets,
            parameters=dict(context.arguments),
            risk_level=risk_level,
            provenance=[item.to_dict() for item in context.provenance],
            steps=[step],
        )
        return plan.model_copy(update={"risk_level": score_plan(plan)})

    def _from_text(self, context: RuntimeContext, *, plan_id: str | None = None) -> ExecutionPlan:
        text = context.model_output or context.prompt or ""
        payload = self._json_payload(text)
        tool_name = self._string_value(payload, "requested_tool", "tool_name", "tool") or self._match(_TOOL_RE, text)
        intent = self._string_value(payload, "intent") or self._match(_INTENT_RE, text) or self._intent_from_tool(tool_name)
        parameters = self._dict_value(payload, "parameters", "arguments")
        targets = self._list_value(payload, "targets")
        target = self._string_value(payload, "target") or self._match(_TARGET_RE, text)
        if target and target not in targets:
            targets.append(target)
        requested_capabilities = self._list_value(payload, "requested_capabilities", "capabilities")
        risk_level = risk_for_tool(tool_name)
        step = PlanStep(
            intent=intent,
            tool_name=tool_name,
            capability=requested_capabilities[0] if requested_capabilities else None,
            target=targets[0] if targets else None,
            parameters=parameters,
            risk_level=risk_level,
            order=1,
        )
        plan_kwargs = {"plan_id": plan_id} if plan_id is not None else {}
        plan = ExecutionPlan(
            **plan_kwargs,
            trace_id=context.trace_id,
            agent_name=context.agent_name,
            user_input=context.prompt,
            model_output=context.model_output,
            intent=intent,
            requested_tool=tool_name,
            requested_capabilities=requested_capabilities,
            targets=targets,
            parameters=parameters,
            risk_level=risk_level,
            provenance=[item.to_dict() for item in context.provenance],
            steps=[step],
        )
        return plan.model_copy(update={"risk_level": score_plan(plan)})

    @staticmethod
    def _intent_from_tool(tool_name: str | None) -> str:
        if not tool_name:
            return "unknown"
        return tool_name

    @staticmethod
    def _requested_capabilities(context: RuntimeContext, tool_name: str | None) -> list[str]:
        if context.allowed_capabilities:
            return list(context.allowed_capabilities)
        if not tool_name:
            return []
        return [tool_name.replace("_", ".")]

    @staticmethod
    def _targets_from_arguments(arguments: dict[str, Any]) -> list[str]:
        targets: list[str] = []
        for key in ("target", "service", "customer_id", "account_id", "name", "to"):
            value = arguments.get(key)
            if value is not None:
                targets.append(str(value))
        return targets

    @staticmethod
    def _json_payload(text: str) -> dict[str, Any]:
        match = _JSON_RE.search(text)
        if not match:
            return {}
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _match(pattern: re.Pattern[str], text: str) -> str | None:
        match = pattern.search(text)
        return match.group(1) if match else None

    @staticmethod
    def _string_value(payload: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if value is not None and not isinstance(value, (dict, list)):
                return str(value)
        return None

    @staticmethod
    def _dict_value(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, dict):
                return dict(value)
        return {}

    @staticmethod
    def _list_value(payload: dict[str, Any], *keys: str) -> list[str]:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [str(item) for item in value]
            if value is not None and not isinstance(value, dict):
                return [str(value)]
        return []


def extract_plan(context: RuntimeContext, *, plan_id: str | None = None) -> ExecutionPlan:
    return PlanExtractor().extract(context, plan_id=plan_id)
