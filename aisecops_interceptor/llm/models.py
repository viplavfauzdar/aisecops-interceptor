from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass(slots=True)
class LLMMessage:
    role: str
    content: str


@dataclass(slots=True)
class LLMRequest:
    messages: List[LLMMessage]
    model: Optional[str] = None
    temperature: Optional[float] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class LLMResponse:
    content: str
    model: Optional[str] = None
    provider: Optional[str] = None
