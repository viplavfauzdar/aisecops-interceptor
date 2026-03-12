from abc import ABC, abstractmethod
from .models import LLMRequest, LLMResponse


class LLMClient(ABC):

    @abstractmethod
    async def chat(self, request: LLMRequest) -> LLMResponse:
        ...
