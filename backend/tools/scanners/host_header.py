"""Host Header Injection Scanner."""
from __future__ import annotations

import asyncio
import httpx

HOST_INJECTION_HEADERS = [
    ("Host", "evil.com"),
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-For", "evil.com"),
    ("X-Host", "evil.com"),
    ("X-Remote-IP", "evil.com"),
    ("X-Client-IP", "evil.com"),
    ("X-Remote-Addr", "evil.com"),
]


async def scan_host_header(
    url: str,
    headers: dict | None = None,
) -> list[dict]:
    findings: list[dict] = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        try:
            baseline = await client.get(url, headers=headers or {})
            baseline_body = baseline.text
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for header_name, header_value in HOST_INJECTION_HEADERS:
            try:
                test_headers = {**(headers or {}), header_name: header_value}
                resp = await client.get(url, headers=test_headers)
                body = resp.text

                if "evil.com" in body and "evil.com" not in baseline_body:
                    findings.append({
                        "type": "host_header_injection",
                        "url": url,
                        "header": f"{header_name}: {header_value}",
                        "evidence": "Injected host reflected in response body",
                        "confidence": 85,
                    })

                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append({
                            "type": "host_header_injection",
                            "url": url,
                            "header": f"{header_name}: {header_value}",
                            "evidence": f"Redirect to injected host: {location}",
                            "confidence": 90,
                        })
            except Exception:
                continue
            await asyncio.sleep(0.05)

    return findings
