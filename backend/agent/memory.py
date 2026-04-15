from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentMemory:
    """Short-term and long-term memory for a single scan session."""

    scan_id: str
    target: str
    messages: list[dict] = field(default_factory=list)

    # Structured recon data
    subdomains: list[str] = field(default_factory=list)
    technologies: dict[str, Any] = field(default_factory=dict)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    parameters: dict[str, list[str]] = field(default_factory=dict)
    js_endpoints: list[str] = field(default_factory=list)
    cloud_assets: list[str] = field(default_factory=list)

    # Findings collected during the scan
    raw_findings: list[dict] = field(default_factory=list)
    verified_findings: list[dict] = field(default_factory=list)

    # Loaded knowledge context
    loaded_knowledge: dict[str, Any] = field(default_factory=dict)

    # Counters
    tool_calls_made: int = 0
    max_tool_calls: int = 200

    def add_message(self, role: str, content: str, **kwargs: Any) -> None:
        msg: dict = {"role": role, "content": content, **kwargs}
        self.messages.append(msg)

    def add_tool_result(self, tool_call_id: str, result: str) -> None:
        self.messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        })
        self.tool_calls_made += 1

    def add_finding(self, finding: dict) -> None:
        self.raw_findings.append(finding)

    def add_verified_finding(self, finding: dict) -> None:
        self.verified_findings.append(finding)

    def get_summary(self) -> dict:
        return {
            "target": self.target,
            "subdomains_found": len(self.subdomains),
            "technologies": self.technologies,
            "open_ports": {h: len(p) for h, p in self.open_ports.items()},
            "parameters_found": sum(len(v) for v in self.parameters.values()),
            "raw_findings": len(self.raw_findings),
            "verified_findings": len(self.verified_findings),
            "tool_calls": self.tool_calls_made,
        }

    @property
    def budget_remaining(self) -> int:
        return max(0, self.max_tool_calls - self.tool_calls_made)
