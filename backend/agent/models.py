from __future__ import annotations

from dataclasses import dataclass

MODEL_REGISTRY: dict[str, "ModelInfo"] = {}


@dataclass(frozen=True)
class ModelInfo:
    id: str
    name: str
    role: str
    context_window: int
    supports_tools: bool
    supports_streaming: bool
    cost_per_1k_input: float
    cost_per_1k_output: float


def _register(m: ModelInfo) -> None:
    MODEL_REGISTRY[m.id] = m


_register(ModelInfo(
    id="anthropic/claude-sonnet-4",
    name="Claude Sonnet 4",
    role="reasoning",
    context_window=200_000,
    supports_tools=True,
    supports_streaming=True,
    cost_per_1k_input=0.003,
    cost_per_1k_output=0.015,
))

_register(ModelInfo(
    id="anthropic/claude-3.5-haiku",
    name="Claude 3.5 Haiku",
    role="fast",
    context_window=200_000,
    supports_tools=True,
    supports_streaming=True,
    cost_per_1k_input=0.0008,
    cost_per_1k_output=0.004,
))

_register(ModelInfo(
    id="openai/gpt-4o",
    name="GPT-4o",
    role="coding",
    context_window=128_000,
    supports_tools=True,
    supports_streaming=True,
    cost_per_1k_input=0.0025,
    cost_per_1k_output=0.01,
))

_register(ModelInfo(
    id="meta-llama/llama-3.3-70b-instruct",
    name="Llama 3.3 70B",
    role="fallback",
    context_window=131_072,
    supports_tools=True,
    supports_streaming=True,
    cost_per_1k_input=0.0003,
    cost_per_1k_output=0.0003,
))


def get_model_for_role(role: str, overrides: dict[str, str] | None = None) -> str:
    from backend.config import settings
    merged = {**settings.models, **(overrides or {})}
    return merged.get(role, merged["reasoning"])


def list_models() -> list[dict]:
    return [
        {
            "id": m.id,
            "name": m.name,
            "role": m.role,
            "context_window": m.context_window,
            "supports_tools": m.supports_tools,
        }
        for m in MODEL_REGISTRY.values()
    ]
