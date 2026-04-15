"""Tests for tool definitions registry."""
from backend.agent.tools import TOOL_DEFINITIONS


def test_tool_definitions_not_empty():
    assert len(TOOL_DEFINITIONS) >= 10


def test_all_tools_have_required_fields():
    for tool in TOOL_DEFINITIONS:
        assert tool["type"] == "function"
        func = tool["function"]
        assert "name" in func
        assert "description" in func
        assert "parameters" in func
        assert func["parameters"]["type"] == "object"
        assert "properties" in func["parameters"]


def test_tool_names_unique():
    names = [t["function"]["name"] for t in TOOL_DEFINITIONS]
    assert len(names) == len(set(names)), f"Duplicate tool names: {[n for n in names if names.count(n) > 1]}"


def test_key_tools_exist():
    names = {t["function"]["name"] for t in TOOL_DEFINITIONS}
    expected = {
        "subdomain_enum", "port_scan", "tech_fingerprint",
        "http_request", "vuln_scan", "nuclei_scan",
        "verify_finding", "load_knowledge",
    }
    assert expected.issubset(names), f"Missing tools: {expected - names}"


def test_vuln_scan_enum_values():
    vuln_tool = next(t for t in TOOL_DEFINITIONS if t["function"]["name"] == "vuln_scan")
    scan_types = vuln_tool["function"]["parameters"]["properties"]["scan_type"]["enum"]
    assert "xss" in scan_types
    assert "sqli" in scan_types
    assert "ssrf" in scan_types
    assert "idor" in scan_types
