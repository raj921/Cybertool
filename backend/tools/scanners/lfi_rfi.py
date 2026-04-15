"""LFI/RFI Scanner -- local and remote file inclusion detection."""
from __future__ import annotations

import re
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

from backend.knowledge.loader import load_category

LFI_INDICATORS = [
    re.compile(r'root:.*?:0:0:', re.I),
    re.compile(r'\[boot loader\]', re.I),
    re.compile(r'\[extensions\]', re.I),
    re.compile(r'<?php', re.I),
    re.compile(r'PD9waHAg', re.I),  # base64 of <?php
]


async def scan_lfi(
    url: str,
    params: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
) -> list[dict]:
    findings: list[dict] = []
    kb = load_category("lfi")
    payloads = kb.get("payloads", {}).get("basic", [])
    wrapper_payloads = kb.get("payloads", {}).get("php_wrappers", [])
    encoding_payloads = list(kb.get("payloads", {}).get("encoding_bypass", {}).values())

    all_payloads = payloads + wrapper_payloads[:5] + encoding_payloads[:3]

    parsed = urlparse(url)
    test_params = params or parse_qs(parsed.query)
    if not test_params:
        return findings

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        try:
            baseline = await client.request(method, url, headers=headers or {})
            baseline_body = baseline.text
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for param_name in test_params:
            for payload in all_payloads[:20]:
                test_p = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_p[param_name] = payload

                try:
                    if method.upper() == "GET":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_p)}"
                        resp = await client.get(test_url, headers=headers or {})
                    else:
                        resp = await client.post(url, data=test_p, headers=headers or {})

                    body = resp.text
                    for indicator in LFI_INDICATORS:
                        if indicator.search(body) and not indicator.search(baseline_body):
                            findings.append({
                                "type": "lfi",
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "evidence": indicator.pattern,
                                "confidence": 90,
                            })
                            break
                except Exception:
                    continue
                await asyncio.sleep(0.05)

    return findings
