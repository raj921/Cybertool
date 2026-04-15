"""Tests for OpenRouter LLM client construction and config."""
from backend.agent.llm import OpenRouterClient
from backend.agent.models import get_model_for_role, list_models, MODEL_REGISTRY


def test_client_init_default():
    client = OpenRouterClient(api_key="test-key")
    assert client.api_key == "test-key"
    assert "openrouter.ai" in client.base_url


def test_model_registry_populated():
    assert len(MODEL_REGISTRY) >= 4
    assert "anthropic/claude-sonnet-4" in MODEL_REGISTRY
    assert "openai/gpt-4o" in MODEL_REGISTRY


def test_get_model_for_role():
    model = get_model_for_role("reasoning")
    assert "claude" in model or "anthropic" in model

    model = get_model_for_role("fast")
    assert "haiku" in model

    model = get_model_for_role("coding")
    assert "gpt" in model


def test_get_model_with_override():
    model = get_model_for_role("reasoning", overrides={"reasoning": "custom/model-x"})
    assert model == "custom/model-x"


def test_list_models():
    models = list_models()
    assert len(models) >= 4
    assert all("id" in m for m in models)
    assert all("name" in m for m in models)


def test_tool_result_message():
    client = OpenRouterClient(api_key="test")
    msg = client._build_tool_result_message("tc_123", '{"result": "ok"}')
    assert msg["role"] == "tool"
    assert msg["tool_call_id"] == "tc_123"
    assert msg["content"] == '{"result": "ok"}'
