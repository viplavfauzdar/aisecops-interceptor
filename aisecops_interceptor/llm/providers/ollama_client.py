import httpx

from ..base import LLMClient
from ..models import LLMRequest, LLMResponse


class OllamaClient(LLMClient):

    def __init__(self, base_url: str, model: str, timeout_seconds: int = 60):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    async def chat(self, request: LLMRequest) -> LLMResponse:

        prompt = "\n".join([f"{m.role}: {m.content}" for m in request.messages])

        payload = {
            "model": request.model or self.model,
            "prompt": prompt,
            "stream": False,
        }

        url = f"{self.base_url}/api/generate"

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()

        return LLMResponse(
            content=data.get("response", "").strip(),
            model=request.model or self.model,
            provider="ollama",
        )
