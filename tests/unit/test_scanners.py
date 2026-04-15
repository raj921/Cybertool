"""Tests for vulnerability scanners -- unit tests with mocked HTTP responses."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from backend.tools.scanners.xss import scan_xss, REFLECTION_MARKERS
from backend.tools.scanners.sqli import scan_sqli, SQL_ERROR_PATTERNS
from backend.tools.scanners.lfi_rfi import scan_lfi, LFI_INDICATORS


def test_xss_reflection_markers():
    assert len(REFLECTION_MARKERS) >= 5
    test_body = '<img src=x onerror=alert(1)>'
    assert any(m.search(test_body) for m in REFLECTION_MARKERS)


def test_xss_safe_context_detection():
    safe_body = '<!-- <script>alert(1)</script> -->'
    from backend.tools.scanners.xss import SAFE_CONTEXTS
    assert any(p.search(safe_body) for p in SAFE_CONTEXTS)


def test_sqli_error_patterns():
    assert len(SQL_ERROR_PATTERNS) >= 8
    test_bodies = [
        "You have an error in your SQL syntax near MySQL",
        "Warning: mysqli_query()",
        "ORA-00933: SQL command not properly ended",
        "SQLSTATE[42000]",
    ]
    for body in test_bodies:
        assert any(p.search(body) for p in SQL_ERROR_PATTERNS), f"Pattern not matched: {body}"


def test_lfi_indicators():
    assert len(LFI_INDICATORS) >= 3
    assert any(p.search("root:x:0:0:root:/root:/bin/bash") for p in LFI_INDICATORS)
    assert any(p.search("PD9waHAg") for p in LFI_INDICATORS)


@pytest.mark.asyncio
async def test_scan_xss_no_params():
    results = await scan_xss("http://example.com/page")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_scan_sqli_no_params():
    results = await scan_sqli("http://nonexistent.invalid/page")
    assert isinstance(results, list)
    if results:
        assert "error" in results[0]


@pytest.mark.asyncio
async def test_scan_lfi_no_params():
    results = await scan_lfi("http://example.com/page")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_vuln_scan_routing():
    from backend.tools.runner import execute_tool
    result = await execute_tool("vuln_scan", {
        "scan_type": "xss",
        "url": "http://example.com/search?q=test",
    })
    assert result["scan_type"] == "xss"
    assert "findings" in result


@pytest.mark.asyncio
async def test_vuln_scan_sqli_routing():
    from backend.tools.runner import execute_tool
    result = await execute_tool("vuln_scan", {
        "scan_type": "sqli",
        "url": "http://example.com/item?id=1",
    })
    assert result["scan_type"] == "sqli"


@pytest.mark.asyncio
async def test_vuln_scan_stub_fallback():
    from backend.tools.runner import execute_tool
    result = await execute_tool("vuln_scan", {
        "scan_type": "cors",
        "url": "http://example.com",
    })
    assert result["scan_type"] == "cors"
    assert "raw" in result
