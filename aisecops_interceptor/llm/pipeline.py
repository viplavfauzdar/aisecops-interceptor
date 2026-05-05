from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from aisecops_interceptor.core.context import RuntimeContext
from aisecops_interceptor.core.events import RuntimeEvent
from aisecops_interceptor.guard.models import GuardResult
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
    def __init__(
        self,
        *,
        client: LLMClient,
        event_sink: LLMEventSink | None = None,
        pre_llm_hook: Callable[[str], GuardResult] | None = None,
    ) -> None:
        self.client = client
        self.event_sink = event_sink
        self.pre_llm_hook = pre_llm_hook

    def _emit_event(
        self,
        *,
        event_type: str,
        decision: str,
        reason: str | None = None,
        stage: str | None = None,
        context: RuntimeContext | None = None,
        trace_id: str | None = None,
        payload: dict[str, object] | None = None,
    ) -> None:
        if self.event_sink is None:
            return
        self.event_sink(
            RuntimeEvent.llm_event(
                event_type=event_type,
                decision=decision,
                reason=reason,
                stage=stage,
                context=context,
                trace_id=trace_id,
                audit_kind=event_type,
                payload=payload,
            )
        )

    async def chat(self, request: LLMRequest, context: RuntimeContext | None = None) -> LLMResponse:
        prompt_text = "\n".join(f"{m.role}: {m.content}" for m in request.messages)
        trace_id = context.ensure_trace_id() if context is not None else (request.correlation_id or uuid4().hex)
        self._emit_event(
            event_type="user_input",
            decision="observed",
            reason="User input received",
            stage="input",
            context=context,
            trace_id=trace_id,
            payload={
                "message_count": len(request.messages),
                "model": request.model,
                "prompt": prompt_text,
            },
        )
        if self.pre_llm_hook is not None:
            precheck_result = self.pre_llm_hook(prompt_text)
            if not precheck_result.allowed:
                reason = (
                    precheck_result.findings[0].message
                    if precheck_result.findings
                    else "Local pre-LLM hook blocked request"
                )
                self._emit_event(
                    event_type="prompt_blocked",
                    decision="blocked",
                    reason=reason,
                    stage="input",
                    context=context,
                    trace_id=trace_id,
                    payload={"source": "pre_llm_hook"},
                )
                raise LLMGuardViolationError("input", reason)
        input_result = inspect_prompt(prompt_text)
        if not input_result.allowed:
            reason = input_result.findings[0].message if input_result.findings else "Input inspection blocked request"
            self._emit_event(
                event_type="prompt_blocked",
                decision="blocked",
                reason=reason,
                stage="input",
                context=context,
                trace_id=trace_id,
            )
            raise LLMGuardViolationError("input", reason)
        self._emit_event(
            event_type="prompt_allowed",
            decision="allowed",
            reason="Prompt allowed",
            stage="input",
            context=context,
            trace_id=trace_id,
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
                trace_id=trace_id,
            )
            raise LLMGuardViolationError("output", reason)
        self._emit_event(
            event_type="output_allowed",
            decision="allowed",
            reason="Output allowed",
            stage="output",
            context=context,
            trace_id=trace_id,
        )
        self._emit_event(
            event_type="final_output",
            decision="allowed",
            reason="Final output emitted",
            stage="output",
            context=context,
            trace_id=trace_id,
            payload={
                "content": response.content,
                "model": response.model,
                "provider": response.provider,
            },
        )

        return response
