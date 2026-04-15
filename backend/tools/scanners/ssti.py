"""SSTI Scanner -- Server-Side Template Injection detection."""
from __future__ import annotations

import asyncio
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("#{7*7}", "49"),
    ("{{config}}", "SECRET_KEY"),
    ("{{self.__class__}}", "__class__"),
]


async def scan_ssti(
    url: str,
    params: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
) -> list[dict]:
    findings: list[dict] = []
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
            for payload, expected in SSTI_PAYLOADS:
                test_p = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_p[param_name] = payload

                try:
                    if method.upper() == "GET":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_p)}"
                        resp = await client.get(test_url, headers=headers or {})
                    else:
                        resp = await client.post(url, data=test_p, headers=headers or {})

                    if expected in resp.text and expected not in baseline_body:
                        findings.append({
                            "type": "ssti",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"Template evaluated: {expected} found in response",
                            "confidence": 90,
                        })
                except Exception:
                    continue
                await asyncio.sleep(0.05)

    return findings
