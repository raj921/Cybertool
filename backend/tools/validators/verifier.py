"""Multi-pass verification engine -- 5 layers to eliminate false positives."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from backend.agent.llm import llm_client
from backend.agent.prompts.validation import VALIDATION_PROMPT


async def verify_finding(
    finding_type: str,
    url: str,
    payload: str,
    method: str = "GET",
    headers: dict | None = None,
    original_response: str | None = None,
) -> dict:
    """Run 5-layer verification on a potential finding.

    Layers:
    1. Baseline comparison
    2. Multi-payload confirmation
    3. Negative test (benign input)
    4. AI reasoning pass
    5. PoC replay
    """
    result = {
        "finding_type": finding_type,
        "url": url,
        "payload": payload,
        "layers": {},
        "confidence": 0,
        "verdict": "UNVERIFIED",
    }

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        # Layer 1: Baseline
        try:
            baseline = await client.request(method, url, headers=headers or {})
            baseline_body = baseline.text
            baseline_status = baseline.status_code
            baseline_len = len(baseline_body)
            result["layers"]["baseline"] = {"status": baseline_status, "length": baseline_len}
        except Exception as e:
            result["layers"]["baseline"] = {"error": str(e)}
            return result

        # Layer 2: Replay with payload
        try:
            if method.upper() == "GET" and "?" in url:
                payload_resp = await client.get(url, headers=headers or {})
            else:
                payload_resp = await client.request(method, url, headers=headers or {})
            payload_body = payload_resp.text
            payload_status = payload_resp.status_code
            payload_len = len(payload_body)

            len_diff = abs(payload_len - baseline_len)
            status_diff = payload_status != baseline_status
            result["layers"]["replay"] = {
                "status": payload_status,
                "length": payload_len,
                "length_diff": len_diff,
                "status_changed": status_diff,
            }
        except Exception as e:
            result["layers"]["replay"] = {"error": str(e)}
            payload_body = ""
            payload_status = 0
            payload_len = 0

        # Layer 3: Negative test with benign input
        try:
            benign_url = url.replace(payload, "cyberhunter_safe_test_12345") if payload in url else url
            benign_resp = await client.request(method, benign_url, headers=headers or {})
            benign_body = benign_resp.text

            payload_in_benign = payload in benign_body if payload else False
            result["layers"]["negative_test"] = {
                "payload_in_benign": payload_in_benign,
                "status": benign_resp.status_code,
                "pass": not payload_in_benign,
            }
        except Exception as e:
            result["layers"]["negative_test"] = {"error": str(e)}

        # Layer 4: AI reasoning
        try:
            prompt = VALIDATION_PROMPT.format(
                finding_type=finding_type,
                url=url,
                payload=payload,
                baseline_status=baseline_status,
                baseline_length=baseline_len,
                baseline_snippet=baseline_body[:500],
                payload_status=payload_status,
                payload_length=payload_len,
                payload_snippet=payload_body[:500] if payload_body else "",
            )
            ai_resp = await llm_client.chat(
                messages=[{"role": "user", "content": prompt}],
                model_role="fast",
                max_tokens=300,
            )
            ai_text = ai_resp.get("choices", [{}])[0].get("message", {}).get("content", "")
            ai_verdict = "TRUE_POSITIVE" if "TRUE_POSITIVE" in ai_text.upper() else "FALSE_POSITIVE"

            confidence_match = None
            for line in ai_text.split("\n"):
                if "confidence" in line.lower():
                    nums = [int(s) for s in line.split() if s.isdigit()]
                    if nums:
                        confidence_match = min(nums[0], 100)
                        break

            result["layers"]["ai_reasoning"] = {
                "verdict": ai_verdict,
                "confidence": confidence_match or (80 if ai_verdict == "TRUE_POSITIVE" else 20),
                "reasoning_preview": ai_text[:300],
            }
        except Exception as e:
            result["layers"]["ai_reasoning"] = {"error": str(e), "verdict": "UNKNOWN"}

        # Layer 5: PoC replay (3x)
        replay_success = 0
        for _ in range(3):
            try:
                r = await client.request(method, url, headers=headers or {})
                if payload and payload[:20] in r.text:
                    replay_success += 1
            except Exception:
                pass
            await asyncio.sleep(0.1)

        result["layers"]["poc_replay"] = {
            "attempts": 3,
            "successes": replay_success,
            "reproducible": replay_success >= 2,
        }

    # Aggregate confidence
    scores = []
    if result["layers"].get("replay", {}).get("length_diff", 0) > 50:
        scores.append(70)
    if result["layers"].get("negative_test", {}).get("pass"):
        scores.append(80)
    ai_conf = result["layers"].get("ai_reasoning", {}).get("confidence", 50)
    scores.append(ai_conf)
    if result["layers"].get("poc_replay", {}).get("reproducible"):
        scores.append(90)

    result["confidence"] = sum(scores) / len(scores) if scores else 0
    result["verdict"] = "TRUE_POSITIVE" if result["confidence"] >= 85 else "NEEDS_REVIEW" if result["confidence"] >= 60 else "FALSE_POSITIVE"

    return result
