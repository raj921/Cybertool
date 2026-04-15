"""Tests for agent engine core loop."""
import asyncio
import pytest
from unittest.mock import AsyncMock

from backend.agent.engine import AgentEngine


@pytest.fixture
def mock_llm_response():
    return {
        "choices": [{
            "message": {
                "content": "[THINK] I will start by enumerating subdomains.\n[COMPLETE] Done.",
            },
            "finish_reason": "stop",
        }],
    }


@pytest.mark.asyncio
async def test_engine_init():
    engine = AgentEngine(scan_id="test1", target="example.com")
    assert engine.scan_id == "test1"
    assert engine.target == "example.com"
    assert engine.memory.budget_remaining == 200


@pytest.mark.asyncio
async def test_engine_emits_events(mock_llm_response):
    engine = AgentEngine(scan_id="test2", target="example.com")
    engine.client = AsyncMock()
    engine.client.chat = AsyncMock(return_value=mock_llm_response)

    collected_events = []

    async def collect(e):
        collected_events.append(e)

    engine.on_event(collect)

    await engine.run()

    event_types = [e["type"] for e in collected_events]
    assert "status" in event_types
    assert "thinking" in event_types


@pytest.mark.asyncio
async def test_engine_stops_on_complete(mock_llm_response):
    engine = AgentEngine(scan_id="test3", target="example.com")
    engine.client = AsyncMock()
    engine.client.chat = AsyncMock(return_value=mock_llm_response)

    summary = await engine.run()
    assert isinstance(summary, dict)
    assert summary["target"] == "example.com"


@pytest.mark.asyncio
async def test_engine_handles_tool_calls():
    tool_response = {
        "choices": [{
            "message": {
                "content": "",
                "tool_calls": [{
                    "id": "tc_1",
                    "function": {
                        "name": "subdomain_enum",
                        "arguments": '{"target": "example.com"}',
                    },
                }],
            },
            "finish_reason": "tool_calls",
        }],
    }
    complete_response = {
        "choices": [{
            "message": {"content": "[COMPLETE] Done."},
            "finish_reason": "stop",
        }],
    }

    engine = AgentEngine(scan_id="test4", target="example.com")
    engine.client = AsyncMock()
    engine.client.chat = AsyncMock(side_effect=[tool_response, complete_response])

    tool_executor = AsyncMock(return_value={"subdomains": ["a.example.com"]})
    engine._tool_executor = tool_executor

    collected_events = []

    async def collect(e):
        collected_events.append(e)

    engine.on_event(collect)

    await engine.run()

    tool_executor.assert_called_once_with("subdomain_enum", {"target": "example.com"})
    tool_event_types = [e["type"] for e in collected_events]
    assert "tool_start" in tool_event_types
    assert "tool_result" in tool_event_types
