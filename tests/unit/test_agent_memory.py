"""Tests for agent memory."""
from backend.agent.memory import AgentMemory


def test_memory_init():
    mem = AgentMemory(scan_id="abc123", target="example.com")
    assert mem.scan_id == "abc123"
    assert mem.target == "example.com"
    assert mem.messages == []
    assert mem.budget_remaining == 200


def test_add_message():
    mem = AgentMemory(scan_id="abc", target="t.com")
    mem.add_message("system", "You are CyberHunter")
    mem.add_message("user", "Hunt example.com")
    assert len(mem.messages) == 2
    assert mem.messages[0]["role"] == "system"


def test_add_tool_result_decrements_budget():
    mem = AgentMemory(scan_id="abc", target="t.com")
    assert mem.budget_remaining == 200

    mem.add_tool_result("tc_1", '{"status": "ok"}')
    assert mem.budget_remaining == 199
    assert mem.tool_calls_made == 1
    assert mem.messages[-1]["role"] == "tool"


def test_add_finding():
    mem = AgentMemory(scan_id="abc", target="t.com")
    finding = {"type": "xss", "severity": "high", "url": "https://t.com/search"}
    mem.add_finding(finding)
    assert len(mem.raw_findings) == 1


def test_get_summary():
    mem = AgentMemory(scan_id="abc", target="t.com")
    mem.subdomains = ["a.t.com", "b.t.com"]
    mem.technologies = {"a.t.com": {"server": "nginx"}}
    mem.add_finding({"type": "xss"})
    mem.add_verified_finding({"type": "xss", "confidence": 95})

    summary = mem.get_summary()
    assert summary["subdomains_found"] == 2
    assert summary["raw_findings"] == 1
    assert summary["verified_findings"] == 1
