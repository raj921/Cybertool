"""XSS Scanner -- tests for reflected, stored, and DOM-based XSS."""
from __future__ import annotations

import re
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx

from backend.knowledge.loader import get_payloads_for_vuln


REFLECTION_MARKERS = [
    re.compile(r'<script>alert\(1\)</script>', re.I),
    re.compile(r'onerror\s*=\s*alert', re.I),
    re.compile(r'onload\s*=\s*alert', re.I),
    re.compile(r'ontoggle\s*=', re.I),
    re.compile(r'<svg\s+onload', re.I),
    re.compile(r'<img\s+[^>]*onerror', re.I),
]

SAFE_CONTEXTS = [
    re.compile(r'<!--.*?-->', re.S),
    re.compile(r'<textarea[^>]*>.*?</textarea>', re.S | re.I),
]


async def scan_xss(
    url: str,
    params: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
    payloads: list[str] | None = None,
    waf: str | None = None,
) -> list[dict]:
    """Scan a URL for XSS vulnerabilities. Returns list of findings."""
    if not payloads:
        kb = get_payloads_for_vuln("xss", waf=waf)
        payloads = kb.get("payloads", [])[:15]
        if waf:
            payloads = kb.get("waf_bypass_payloads", [])[:10] + payloads

    parsed = urlparse(url)
    test_params = params or parse_qs(parsed.query)
    if not test_params:
        test_params = {"q": ["test"]}

    findings: list[dict] = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        # Get baseline
        try:
            baseline = await client.request(method, url, headers=headers or {})
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for param_name in test_params:
            for payload in payloads:
                test_params_copy = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                test_params_copy[param_name] = payload

                try:
                    if method.upper() == "GET":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_copy)}"
                        resp = await client.get(test_url, headers=headers or {})
                    else:
                        resp = await client.post(url, data=test_params_copy, headers=headers or {})

                    body = resp.text

                    # Check if payload is reflected in an executable context
                    reflected = False
                    for marker in REFLECTION_MARKERS:
                        if marker.search(body):
                            in_safe = False
                            for safe in SAFE_CONTEXTS:
                                safe_matches = safe.findall(body)
                                for sm in safe_matches:
                                    if marker.search(sm):
                                        in_safe = True
                                        break
                            if not in_safe:
                                reflected = True
                                break

                    if reflected or (payload in body and payload not in baseline_body):
                        findings.append({
                            "type": "xss",
                            "subtype": "reflected",
                            "url": test_url if method.upper() == "GET" else url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": body[body.find(payload[:20]):body.find(payload[:20]) + 200] if payload[:20] in body else "",
                            "confidence": 85 if reflected else 60,
                        })
                except Exception:
                    continue

                await asyncio.sleep(0.05)

    return findings
