"""Tests for tool runner."""
import pytest
from backend.tools.runner import execute_tool, TOOL_REGISTRY


def test_tool_registry_populated():
    assert len(TOOL_REGISTRY) >= 10
    assert "subdomain_enum" in TOOL_REGISTRY
    assert "http_request" in TOOL_REGISTRY
    assert "tech_fingerprint" in TOOL_REGISTRY
    assert "load_knowledge" in TOOL_REGISTRY
    assert "vuln_scan" in TOOL_REGISTRY


@pytest.mark.asyncio
async def test_load_knowledge_tool():
    result = await execute_tool("load_knowledge", {"category": "xss"})
    assert result["id"] == "xss"
    assert "payloads" in result


@pytest.mark.asyncio
async def test_load_knowledge_unknown():
    result = await execute_tool("load_knowledge", {"category": "nonexistent"})
    assert "error" in result


@pytest.mark.asyncio
async def test_vuln_scan_tool():
    result = await execute_tool("vuln_scan", {"scan_type": "xss", "url": "http://example.com"})
    assert result["scan_type"] == "xss"
    assert "findings" in result


@pytest.mark.asyncio
async def test_unknown_tool():
    result = await execute_tool("totally_fake_tool", {})
    assert "error" in result


@pytest.mark.asyncio
async def test_js_analysis_empty():
    result = await execute_tool("js_analysis", {"urls": []})
    assert "endpoints" in result
    assert "secrets" in result
