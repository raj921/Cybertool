"""SSRF Scanner -- tests for server-side request forgery with various bypass techniques."""
from __future__ import annotations

import asyncio
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

from backend.knowledge.loader import load_category


async def scan_ssrf(
    url: str,
    params: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
    callback_url: str | None = None,
) -> list[dict]:
    findings: list[dict] = []

    kb = load_category("ssrf")
    basic_payloads = kb.get("payloads", {}).get("basic", [])
    cloud_meta = kb.get("payloads", {}).get("cloud_metadata", {})
    ip_bypass = kb.get("payloads", {}).get("ip_bypass", {})

    ssrf_targets = basic_payloads + list(cloud_meta.values()) + list(ip_bypass.values())

    parsed = urlparse(url)
    test_params = params or parse_qs(parsed.query)
    if not test_params:
        return findings

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        # Baseline
        try:
            baseline = await client.request(method, url, headers=headers or {})
            baseline_len = len(baseline.text)
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for param_name in test_params:
            for payload in ssrf_targets[:15]:
                test_p = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_p[param_name] = payload

                try:
                    if method.upper() == "GET":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_p)}"
                        resp = await client.get(test_url, headers=headers or {})
                    else:
                        resp = await client.post(url, data=test_p, headers=headers or {})

                    body = resp.text.lower()

                    indicators = [
                        ("root:", "Local file or /etc/passwd content"),
                        ("ami-id", "AWS metadata exposed"),
                        ("instance-id", "Cloud instance metadata"),
                        ("computeMetadata", "GCP metadata exposed"),
                        ("127.0.0.1", "Localhost content returned"),
                        ("internal", "Internal network content"),
                    ]

                    for indicator, desc in indicators:
                        if indicator.lower() in body and indicator.lower() not in baseline.text.lower():
                            findings.append({
                                "type": "ssrf",
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "evidence": desc,
                                "confidence": 85,
                            })
                            break
                except Exception:
                    continue
                await asyncio.sleep(0.05)

    return findings
