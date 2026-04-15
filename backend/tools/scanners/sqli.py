"""SQL Injection Scanner -- error-based, boolean-blind, time-based detection."""
from __future__ import annotations

import re
import time
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

from backend.knowledge.loader import get_payloads_for_vuln

SQL_ERROR_PATTERNS = [
    re.compile(r'SQL syntax.*?MySQL', re.I),
    re.compile(r'Warning.*?\Wmysqli?_', re.I),
    re.compile(r'PostgreSQL.*?ERROR', re.I),
    re.compile(r'ORA-\d{5}', re.I),
    re.compile(r'Microsoft.*?ODBC.*?SQL Server', re.I),
    re.compile(r'Unclosed quotation mark', re.I),
    re.compile(r'sqlite3\.OperationalError', re.I),
    re.compile(r'pg_query\(\).*?ERROR', re.I),
    re.compile(r'valid MySQL result', re.I),
    re.compile(r'mysql_fetch', re.I),
    re.compile(r'SQLSTATE\[', re.I),
]


async def scan_sqli(
    url: str,
    params: dict | None = None,
    method: str = "GET",
    headers: dict | None = None,
    payloads: list[str] | None = None,
) -> list[dict]:
    findings: list[dict] = []

    if not payloads:
        kb = get_payloads_for_vuln("sqli")
        payloads = kb.get("payloads", [])[:20]

    parsed = urlparse(url)
    test_params = params or parse_qs(parsed.query)
    if not test_params:
        test_params = {"id": ["1"]}

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
        # Baseline
        try:
            baseline = await client.request(method, url, headers=headers or {})
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
            baseline_status = baseline.status_code
        except Exception:
            return [{"error": f"Cannot reach {url}"}]

        for param_name in test_params:
            # Error-based detection
            for payload in payloads[:10]:
                test_p = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_p[param_name] = payload

                try:
                    if method.upper() == "GET":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_p)}"
                        resp = await client.get(test_url, headers=headers or {})
                    else:
                        resp = await client.post(url, data=test_p, headers=headers or {})

                    body = resp.text
                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern.search(body) and not pattern.search(baseline_body):
                            findings.append({
                                "type": "sqli",
                                "subtype": "error_based",
                                "url": test_url if method.upper() == "GET" else url,
                                "param": param_name,
                                "payload": payload,
                                "evidence": pattern.pattern,
                                "confidence": 90,
                            })
                            break
                except Exception:
                    continue
                await asyncio.sleep(0.05)

            # Boolean-blind detection
            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"
            try:
                test_true = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_true[param_name] = test_true[param_name] + true_payload
                test_false = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_false[param_name] = test_false[param_name] + false_payload

                if method.upper() == "GET":
                    resp_true = await client.get(
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_true)}",
                        headers=headers or {},
                    )
                    resp_false = await client.get(
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_false)}",
                        headers=headers or {},
                    )
                else:
                    resp_true = await client.post(url, data=test_true, headers=headers or {})
                    resp_false = await client.post(url, data=test_false, headers=headers or {})

                len_diff = abs(len(resp_true.text) - len(resp_false.text))
                if len_diff > 50 and resp_true.status_code == resp_false.status_code:
                    findings.append({
                        "type": "sqli",
                        "subtype": "boolean_blind",
                        "url": url,
                        "param": param_name,
                        "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                        "evidence": f"Response length diff: {len_diff}",
                        "confidence": 70,
                    })
            except Exception:
                pass

            # Time-based detection
            time_payload = "' AND SLEEP(3)--"
            try:
                test_p = {k: (v[0] if isinstance(v, list) else v) for k, v in test_params.items()}
                test_p[param_name] = test_p[param_name] + time_payload
                start = time.monotonic()
                if method.upper() == "GET":
                    await client.get(
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_p)}",
                        headers=headers or {},
                    )
                else:
                    await client.post(url, data=test_p, headers=headers or {})
                elapsed = time.monotonic() - start

                if elapsed >= 2.5:
                    findings.append({
                        "type": "sqli",
                        "subtype": "time_blind",
                        "url": url,
                        "param": param_name,
                        "payload": time_payload,
                        "evidence": f"Response delayed {elapsed:.1f}s",
                        "confidence": 80,
                    })
            except Exception:
                pass

    return findings
