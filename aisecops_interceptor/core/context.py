from dataclasses import dataclass, field
from typing import Optional, Dict


@dataclass(slots=True)
class RuntimeContext:
    agent_name: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    prompt: Optional[str] = None
    tool_name: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
