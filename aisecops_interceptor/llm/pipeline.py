from __future__ import annotations

from datetime import datetime, timezone

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import LLMSecurityEvent
from aisecops_interceptor.guard.input_inspector import inspect_prompt
from aisecops_interceptor.guard.output_inspector import inspect_output
from aisecops_interceptor.llm.base import LLMClient
from aisecops_interceptor.llm.models import LLMEventSink, LLMRequest, LLMResponse


class LLMGuardViolationError(Exception):
    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage
        self.message = message


class GuardedLLMPipeline:
    def __init__(self, *, client: LLMClient, event_sink: LLMEventSink | None = None) -> None:
        self.client = client
        self.event_sink = event_sink

    def _emit_event(
        self,
        *,
        event_type: str,
        decision: str,
        reason: str | None = None,
        stage: str | None = None,
        context: RuntimeContext | None = None,
    ) -> None:
        if self.event_sink is None:
            return
        self.event_sink(
            LLMSecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                decision=decision,
                reason=reason,
                stage=stage,
                context=context,
            )
        )

    async def chat(self, request: LLMRequest, context: RuntimeContext | None = None) -> LLMResponse:
        prompt_text = "\n".join(f"{m.role}: {m.content}" for m in request.messages)
        input_result = inspect_prompt(prompt_text)
        if not input_result.allowed:
            reason = input_result.findings[0].message if input_result.findings else "Input inspection blocked request"
            self._emit_event(
                event_type="prompt_blocked",
                decision="blocked",
                reason=reason,
                stage="input",
                context=context,
            )
            raise LLMGuardViolationError("input", reason)
        self._emit_event(
            event_type="prompt_allowed",
            decision="allowed",
            stage="input",
            context=context,
        )

        response = await self.client.chat(request)

        output_result = inspect_output(response.content)
        if not output_result.allowed:
            reason = output_result.findings[0].message if output_result.findings else "Output inspection blocked response"
            self._emit_event(
                event_type="output_blocked",
                decision="blocked",
                reason=reason,
                stage="output",
                context=context,
            )
            raise LLMGuardViolationError("output", reason)
        self._emit_event(
            event_type="output_allowed",
            decision="allowed",
            stage="output",
            context=context,
        )

        return response
