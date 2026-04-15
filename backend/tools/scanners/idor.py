"""IDOR Scanner -- Insecure Direct Object Reference detection."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx


async def scan_idor(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    id_param: str | None = None,
) -> list[dict]:
    findings: list[dict] = []
    parsed = urlparse(url)
    path = parsed.path

    # Detect numeric IDs in path segments
    segments = [s for s in path.split("/") if s]
    id_positions = [(i, s) for i, s in enumerate(segments) if s.isdigit()]

    if not id_positions and not id_param:
        return findings

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        # Baseline with original ID
        try:
            baseline = await client.request(method, url, headers=headers or {})
            if baseline.status_code >= 400:
                return findings
            baseline_len = len(baseline.text)
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for idx, orig_id in id_positions:
            orig_num = int(orig_id)
            test_ids = [orig_num - 1, orig_num + 1, orig_num + 2]

            for test_id in test_ids:
                if test_id < 0:
                    continue
                new_segments = segments.copy()
                new_segments[idx] = str(test_id)
                test_path = "/" + "/".join(new_segments)
                test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                if parsed.query:
                    test_url += f"?{parsed.query}"

                try:
                    resp = await client.request(method, test_url, headers=headers or {})
                    if resp.status_code == 200 and abs(len(resp.text) - baseline_len) < baseline_len * 0.5:
                        if resp.text != baseline.text:
                            findings.append({
                                "type": "idor",
                                "url": test_url,
                                "original_url": url,
                                "original_id": orig_id,
                                "tested_id": str(test_id),
                                "evidence": f"Different content returned for ID {test_id} (status {resp.status_code})",
                                "confidence": 70,
                            })
                except Exception:
                    continue
                await asyncio.sleep(0.05)

    return findings
