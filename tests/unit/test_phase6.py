"""Tests for Phase 6: chains, WAF detection, persistent memory."""
import pytest
from pathlib import Path

from backend.knowledge.loader import load_yaml, clear_cache
from backend.agent.persistent_memory import (
    remember_finding, remember_technique, remember_waf_bypass,
    recall_for_target, recall_best_techniques, recall_best_waf_bypasses,
    clear_memory, MEMORY_FILE,
)


@pytest.fixture(autouse=True)
def clean():
    clear_cache()
    clear_memory()
    yield
    clear_memory()


def test_load_chain_redirect_to_ssrf():
    data = load_yaml("chaining/redirect_to_ssrf.yaml")
    assert data["id"] == "redirect_to_ssrf"
    assert data["impact"] == "critical"
    assert len(data["chain"]) >= 3


def test_load_chain_xss_to_ato():
    data = load_yaml("chaining/xss_to_ato.yaml")
    assert data["id"] == "xss_to_ato"
    assert "cookie_steal" in data["chain"][1]["payloads"]


def test_load_chain_idor_to_breach():
    data = load_yaml("chaining/idor_to_data_breach.yaml")
    assert data["id"] == "idor_to_data_breach"


def test_load_chain_oauth_to_ato():
    data = load_yaml("chaining/oauth_to_ato.yaml")
    assert data["id"] == "oauth_to_ato"


def test_persistent_memory_findings():
    remember_finding("example.com", {"type": "xss", "severity": "high", "payload": "<script>"})
    remember_finding("example.com", {"type": "sqli", "severity": "critical"})

    results = recall_for_target("example.com")
    assert len(results) == 2
    assert results[0]["type"] == "xss"

    empty = recall_for_target("nonexistent.com")
    assert empty == []


def test_persistent_memory_techniques():
    remember_technique("laravel", "env_exposure", True)
    remember_technique("laravel", "env_exposure", True)
    remember_technique("laravel", "ignition_rce", True)
    remember_technique("laravel", "debug_mode", False)

    best = recall_best_techniques("laravel")
    assert "env_exposure" in best
    assert best[0] == "env_exposure"


def test_persistent_memory_waf():
    remember_waf_bypass("cloudflare", "<svg onload=alert(1)>", True)
    remember_waf_bypass("cloudflare", "<svg onload=alert(1)>", True)
    remember_waf_bypass("cloudflare", "<script>alert(1)</script>", False)

    best = recall_best_waf_bypasses("cloudflare")
    assert best[0] == "<svg onload=alert(1)>"


def test_persistent_memory_dedup():
    finding = {"type": "xss", "severity": "high", "payload": "<script>", "url": "/search"}
    remember_finding("t.com", finding)
    remember_finding("t.com", finding)

    results = recall_for_target("t.com")
    assert len(results) == 1


def test_waf_signatures():
    from backend.tools.scanners.waf_detect import WAF_SIGNATURES
    assert "cloudflare" in WAF_SIGNATURES
    assert "aws_waf" in WAF_SIGNATURES
    assert "imperva" in WAF_SIGNATURES
    assert len(WAF_SIGNATURES) >= 5
