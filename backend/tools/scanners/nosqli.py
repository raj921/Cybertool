"""NoSQL Injection Scanner -- tests for MongoDB/CouchDB injection."""
from __future__ import annotations

import json
import asyncio

import httpx

from backend.knowledge.loader import load_category


async def scan_nosqli(
    url: str,
    params: dict | None = None,
    method: str = "POST",
    headers: dict | None = None,
) -> list[dict]:
    findings: list[dict] = []
    kb = load_category("nosqli")
    auth_payloads = kb.get("payloads", {}).get("auth_bypass", [])

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        # Baseline with valid-looking creds
        try:
            baseline_data = {"username": "invalid_user_xyz", "password": "invalid_pass_xyz"}
            baseline = await client.post(url, json=baseline_data, headers=headers or {})
            baseline_body = baseline.text
            baseline_status = baseline.status_code
            baseline_len = len(baseline_body)
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for payload_str in auth_payloads:
            try:
                if payload_str.startswith("{"):
                    payload_data = json.loads(payload_str)
                else:
                    payload_data = {}
                    for part in payload_str.split("&"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            if "[$" in k:
                                base = k.split("[")[0]
                                op = k.split("[")[1].rstrip("]")
                                payload_data.setdefault(base, {})[op] = v
                            else:
                                payload_data[k] = v
                    if not payload_data:
                        continue

                resp = await client.post(url, json=payload_data, headers=headers or {})

                if resp.status_code != baseline_status or abs(len(resp.text) - baseline_len) > 100:
                    success_indicators = ["welcome", "dashboard", "profile", "logout", "token", "session"]
                    body_lower = resp.text.lower()
                    if any(ind in body_lower for ind in success_indicators):
                        findings.append({
                            "type": "nosqli",
                            "subtype": "auth_bypass",
                            "url": url,
                            "payload": payload_str,
                            "evidence": f"Status: {resp.status_code}, Length diff: {abs(len(resp.text) - baseline_len)}",
                            "confidence": 85,
                        })
            except (json.JSONDecodeError, Exception):
                continue
            await asyncio.sleep(0.05)

    return findings
