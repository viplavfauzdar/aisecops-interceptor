import httpx

from ..base import LLMClient
from ..models import LLMRequest, LLMResponse


class OpenAIClient(LLMClient):

    def __init__(self, api_key: str, model: str, timeout_seconds: int = 60):
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    async def chat(self, request: LLMRequest) -> LLMResponse:

        url = "https://api.openai.com/v1/chat/completions"

        payload = {
            "model": request.model or self.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "temperature": request.temperature or 0.7,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            r = await client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()

        content = data["choices"][0]["message"]["content"]

        return LLMResponse(
            content=content.strip(),
            model=request.model or self.model,
            provider="openai",
        )
