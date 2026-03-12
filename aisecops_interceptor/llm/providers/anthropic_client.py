import httpx

from ..base import LLMClient
from ..models import LLMRequest, LLMResponse


class AnthropicClient(LLMClient):
    def __init__(self, api_key: str, model: str, timeout_seconds: int = 60, anthropic_version: str = "2023-06-01"):
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.anthropic_version = anthropic_version

    async def chat(self, request: LLMRequest) -> LLMResponse:
        url = "https://api.anthropic.com/v1/messages"

        system_messages = [m.content for m in request.messages if m.role == "system"]
        non_system_messages = [
            {"role": m.role, "content": m.content}
            for m in request.messages
            if m.role != "system"
        ]

        payload = {
            "model": request.model or self.model,
            "max_tokens": 1024,
            "messages": non_system_messages,
        }

        if system_messages:
            payload["system"] = "\n\n".join(system_messages)

        if request.temperature is not None:
            payload["temperature"] = request.temperature

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "content-type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        content_blocks = data.get("content", [])
        text_parts = [block.get("text", "") for block in content_blocks if block.get("type") == "text"]
        content = "".join(text_parts).strip()

        return LLMResponse(
            content=content,
            model=request.model or self.model,
            provider="anthropic",
        )