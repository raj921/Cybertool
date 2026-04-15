"""Core agent engine: the autonomous think -> act -> observe -> reason loop."""
from __future__ import annotations

import json
import asyncio
import traceback
from typing import Any, Callable, Awaitable

from backend.agent.llm import OpenRouterClient, llm_client
from backend.agent.memory import AgentMemory
from backend.agent.tools import TOOL_DEFINITIONS
from backend.agent.prompts.system import SYSTEM_PROMPT


EventCallback = Callable[[dict], Awaitable[None]]


class AgentEngine:
    """Autonomous bug-hunting agent powered by an LLM via OpenRouter."""

    def __init__(
        self,
        scan_id: str,
        target: str,
        scope_config: dict | None = None,
        model_role: str = "reasoning",
        client: OpenRouterClient | None = None,
        tool_executor: Callable[[str, dict], Awaitable[Any]] | None = None,
    ):
        self.scan_id = scan_id
        self.target = target
        self.scope_config = scope_config or {}
        self.model_role = model_role
        self.client = client or llm_client
        self.memory = AgentMemory(scan_id=scan_id, target=target)
        self._on_event: EventCallback | None = None
        self._tool_executor = tool_executor or self._default_tool_executor
        self._running = False

    def on_event(self, callback: EventCallback) -> None:
        self._on_event = callback

    async def _emit(self, event: dict) -> None:
        if self._on_event:
            await self._on_event(event)

    async def run(self) -> dict:
        """Main agent loop. Runs until the agent decides it's done or budget is exhausted."""
        self._running = True
        await self._emit({"type": "status", "status": "running", "scan_id": self.scan_id})

        scope_desc = json.dumps(self.scope_config) if self.scope_config else "default"
        initial_user_msg = (
            f"Hunt for vulnerabilities on target: {self.target}\n"
            f"Scope configuration: {scope_desc}\n"
            f"You have a budget of {self.memory.max_tool_calls} tool calls. "
            f"Start with reconnaissance, then move to vulnerability scanning. Go."
        )

        self.memory.add_message("system", SYSTEM_PROMPT)
        self.memory.add_message("user", initial_user_msg)

        while self._running and self.memory.budget_remaining > 0:
            try:
                response = await self.client.chat(
                    messages=self.memory.messages,
                    model_role=self.model_role,
                    tools=TOOL_DEFINITIONS,
                )
                choice = response.get("choices", [{}])[0]
                message = choice.get("message", {})
                finish_reason = choice.get("finish_reason", "")

                # Text response from the agent
                if message.get("content"):
                    text = message["content"]
                    self.memory.add_message("assistant", text)
                    await self._emit({"type": "thinking", "text": text, "scan_id": self.scan_id})

                    if "[COMPLETE]" in text:
                        self._running = False
                        break

                    if "[FINDING]" in text:
                        await self._emit({"type": "finding_raw", "text": text, "scan_id": self.scan_id})

                # Tool calls
                tool_calls = message.get("tool_calls", [])
                if tool_calls:
                    assistant_msg: dict = {"role": "assistant", "content": message.get("content", "")}
                    assistant_msg["tool_calls"] = tool_calls
                    self.memory.messages.append(assistant_msg)

                    for tc in tool_calls:
                        func = tc.get("function", {})
                        tool_name = func.get("name", "unknown")
                        try:
                            tool_args = json.loads(func.get("arguments", "{}"))
                        except json.JSONDecodeError:
                            tool_args = {}

                        tc_id = tc.get("id", "")
                        await self._emit({
                            "type": "tool_start",
                            "tool": tool_name,
                            "args": tool_args,
                            "scan_id": self.scan_id,
                        })

                        try:
                            result = await self._tool_executor(tool_name, tool_args)
                            result_str = json.dumps(result) if not isinstance(result, str) else result
                        except Exception as exc:
                            result_str = json.dumps({"error": str(exc)})

                        self.memory.add_tool_result(tc_id, result_str)
                        await self._emit({
                            "type": "tool_result",
                            "tool": tool_name,
                            "result_preview": result_str[:500],
                            "scan_id": self.scan_id,
                        })

                if finish_reason == "stop" and not tool_calls:
                    if not message.get("content"):
                        self._running = False

            except Exception as exc:
                error_msg = f"Agent error: {traceback.format_exc()}"
                await self._emit({"type": "error", "text": str(exc), "scan_id": self.scan_id})
                self.memory.add_message("user", f"An error occurred: {exc}. Continue hunting.")
                await asyncio.sleep(1)

        await self._emit({
            "type": "status",
            "status": "completed",
            "scan_id": self.scan_id,
            "summary": self.memory.get_summary(),
        })
        return self.memory.get_summary()

    def stop(self) -> None:
        self._running = False

    @staticmethod
    async def _default_tool_executor(tool_name: str, args: dict) -> Any:
        from backend.tools.runner import execute_tool
        return await execute_tool(tool_name, args)
