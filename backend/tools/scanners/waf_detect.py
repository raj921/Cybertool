"""WAF Detection -- identifies which WAF protects a target and loads appropriate bypass payloads."""
from __future__ import annotations

import asyncio

import httpx

from backend.knowledge.loader import get_waf_bypass_payloads

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "body": ["cloudflare", "attention required"],
        "server": ["cloudflare"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": [],
        "server": [],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "body": ["access denied", "akamai"],
        "server": ["akamaighost"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "body": ["incapsula", "imperva"],
        "server": [],
    },
    "modsecurity": {
        "headers": [],
        "body": ["mod_security", "modsecurity", "not acceptable"],
        "server": [],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["sucuri", "access denied - sucuri"],
        "server": ["sucuri"],
    },
}


async def detect_waf(url: str) -> dict:
    """Detect WAF on a target by analyzing headers and probe responses."""
    detected: list[str] = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        # Normal request
        try:
            resp = await client.get(url)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body_lower = resp.text[:5000].lower()
            server = headers_lower.get("server", "")

            for waf_name, sigs in WAF_SIGNATURES.items():
                for h in sigs["headers"]:
                    if h in headers_lower:
                        detected.append(waf_name)
                        break
                for b in sigs["body"]:
                    if b in body_lower:
                        if waf_name not in detected:
                            detected.append(waf_name)
                        break
                for s in sigs["server"]:
                    if s in server:
                        if waf_name not in detected:
                            detected.append(waf_name)
                        break
        except Exception:
            pass

        # Trigger WAF with a malicious-looking request
        try:
            probe_url = f"{url}?test=<script>alert(1)</script>&id=1' OR 1=1--"
            probe = await client.get(probe_url)
            probe_lower = probe.text[:5000].lower()

            if probe.status_code in (403, 406, 429, 503):
                for waf_name, sigs in WAF_SIGNATURES.items():
                    for b in sigs["body"]:
                        if b in probe_lower and waf_name not in detected:
                            detected.append(waf_name)
        except Exception:
            pass

    bypass_payloads = {}
    for waf in detected:
        bypass_payloads[waf] = get_waf_bypass_payloads(waf)

    return {
        "url": url,
        "waf_detected": detected,
        "bypass_payloads": bypass_payloads,
    }
