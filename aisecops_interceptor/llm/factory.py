from .config import LLMConfig
from .providers.ollama_client import OllamaClient
from .providers.openai_client import OpenAIClient
from .providers.anthropic_client import AnthropicClient


def create_llm_client(config: LLMConfig):

    provider = config.provider.lower()

    if provider == "ollama":
        return OllamaClient(
            base_url=config.base_url or "http://localhost:11434",
            model=config.model or "llama3",
            timeout_seconds=config.timeout_seconds,
        )

    if provider == "openai":
        return OpenAIClient(
            api_key=config.api_key,
            model=config.model or "gpt-4o-mini",
            timeout_seconds=config.timeout_seconds,
        )

    if provider == "anthropic":
        return AnthropicClient(
            api_key=config.api_key,
            model=config.model or "claude-3-5-sonnet-latest",
            timeout_seconds=config.timeout_seconds,
        )

    raise ValueError(f"Unsupported LLM provider: {config.provider}")
