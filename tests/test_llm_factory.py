from aisecops_interceptor.llm.config import LLMConfig
from aisecops_interceptor.llm.factory import create_llm_client
from aisecops_interceptor.llm.providers.anthropic_client import AnthropicClient
from aisecops_interceptor.llm.providers.ollama_client import OllamaClient
from aisecops_interceptor.llm.providers.openai_client import OpenAIClient


def test_factory_creates_ollama_client() -> None:
    client = create_llm_client(LLMConfig(provider="ollama", model="llama3"))
    assert isinstance(client, OllamaClient)


def test_factory_creates_openai_client() -> None:
    client = create_llm_client(LLMConfig(provider="openai", api_key="test-key", model="gpt-4o-mini"))
    assert isinstance(client, OpenAIClient)


def test_factory_creates_anthropic_client() -> None:
    client = create_llm_client(
        LLMConfig(provider="anthropic", api_key="test-key", model="claude-3-5-sonnet-latest")
    )
    assert isinstance(client, AnthropicClient)
