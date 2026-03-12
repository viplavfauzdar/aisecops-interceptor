from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class LLMConfig:
    provider: str = "ollama"
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    timeout_seconds: int = 60
