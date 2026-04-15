"""Persistent agent memory -- remembers successful techniques across scan sessions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.config import settings

MEMORY_FILE = Path(settings.base_dir) / "agent_memory.json"


def _load() -> dict:
    if MEMORY_FILE.exists():
        return json.loads(MEMORY_FILE.read_text())
    return {"targets": {}, "techniques": {}, "waf_bypasses": {}}


def _save(data: dict) -> None:
    MEMORY_FILE.write_text(json.dumps(data, indent=2))


def remember_finding(target: str, finding: dict) -> None:
    """Store a successful finding for future reference."""
    data = _load()
    data["targets"].setdefault(target, [])
    entry = {
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "payload": finding.get("payload", ""),
        "url": finding.get("url", ""),
    }
    if entry not in data["targets"][target]:
        data["targets"][target].append(entry)
    _save(data)


def remember_technique(technology: str, technique: str, success: bool) -> None:
    """Remember which techniques work for which technologies."""
    data = _load()
    key = f"{technology}:{technique}"
    data["techniques"][key] = data["techniques"].get(key, 0) + (1 if success else -1)
    _save(data)


def remember_waf_bypass(waf: str, payload: str, success: bool) -> None:
    """Remember which WAF bypass payloads work."""
    data = _load()
    data["waf_bypasses"].setdefault(waf, {})
    data["waf_bypasses"][waf][payload] = data["waf_bypasses"][waf].get(payload, 0) + (1 if success else -1)
    _save(data)


def recall_for_target(target: str) -> list[dict]:
    """Recall past findings for a target domain."""
    data = _load()
    return data["targets"].get(target, [])


def recall_best_techniques(technology: str) -> list[str]:
    """Recall the most effective techniques for a technology."""
    data = _load()
    prefix = f"{technology}:"
    scored = [(k.split(":", 1)[1], v) for k, v in data["techniques"].items() if k.startswith(prefix)]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [t for t, _ in scored[:10]]


def recall_best_waf_bypasses(waf: str) -> list[str]:
    """Recall the best WAF bypass payloads from past experience."""
    data = _load()
    bypasses = data["waf_bypasses"].get(waf, {})
    scored = sorted(bypasses.items(), key=lambda x: x[1], reverse=True)
    return [p for p, _ in scored[:10]]


def clear_memory() -> None:
    if MEMORY_FILE.exists():
        MEMORY_FILE.unlink()
