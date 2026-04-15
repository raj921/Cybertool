from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")


@dataclass
class Settings:
    # OpenRouter
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Model defaults (user can override from dashboard)
    models: dict[str, str] = field(default_factory=lambda: {
        "reasoning": "anthropic/claude-sonnet-4",
        "fast": "anthropic/claude-3.5-haiku",
        "coding": "openai/gpt-4o",
        "fallback": "meta-llama/llama-3.3-70b-instruct",
    })
    default_model_role: str = "reasoning"

    # Paths
    base_dir: Path = Path(__file__).parent
    knowledge_dir: Path = Path(__file__).parent / "knowledge"
    db_path: str = str(Path(__file__).parent / "cyberhunter.db")

    # Scan defaults
    max_concurrent_tools: int = 10
    request_timeout: int = 30
    rate_limit_per_second: float = 10.0

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    frontend_url: str = "http://localhost:3000"


settings = Settings()
