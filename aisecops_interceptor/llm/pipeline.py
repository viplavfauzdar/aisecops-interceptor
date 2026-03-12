from __future__ import annotations

from aisecops_interceptor.guard.input_inspector import inspect_prompt
from aisecops_interceptor.guard.output_inspector import inspect_output
from aisecops_interceptor.llm.base import LLMClient
from aisecops_interceptor.llm.models import LLMRequest, LLMResponse


class LLMGuardViolationError(Exception):
    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage
        self.message = message


class GuardedLLMPipeline:
    def __init__(self, *, client: LLMClient) -> None:
        self.client = client

    async def chat(self, request: LLMRequest) -> LLMResponse:
        prompt_text = "\n".join(f"{m.role}: {m.content}" for m in request.messages)
        input_result = inspect_prompt(prompt_text)
        if not input_result.allowed:
            reason = input_result.findings[0].message if input_result.findings else "Input inspection blocked request"
            raise LLMGuardViolationError("input", reason)

        response = await self.client.chat(request)

        output_result = inspect_output(response.content)
        if not output_result.allowed:
            reason = output_result.findings[0].message if output_result.findings else "Output inspection blocked response"
            raise LLMGuardViolationError("output", reason)

        return response
