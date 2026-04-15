"""Async tool executor -- maps tool names to implementations and runs them."""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from typing import Any

import httpx

from backend.knowledge.loader import load_category, get_payloads_for_vuln


async def _run_process(cmd: list[str], timeout: int = 60) -> str:
    """Run an external process asynchronously and return stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()  # type: ignore
        return json.dumps({"error": f"Command timed out after {timeout}s"})
    except FileNotFoundError:
        return json.dumps({"error": f"Tool not found: {cmd[0]}"})


async def _http_request(args: dict) -> dict:
    """Execute an HTTP request and return status, headers, body."""
    url = args["url"]
    method = args.get("method", "GET")
    headers = args.get("headers", {})
    body = args.get("body")
    follow = args.get("follow_redirects", True)

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=follow, verify=False) as client:
        resp = await client.request(method, url, headers=headers, content=body)
        body_text = resp.text[:5000]
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": body_text,
            "body_length": len(resp.text),
            "url": str(resp.url),
        }


async def subdomain_enum(args: dict) -> dict:
    target = args["target"]
    methods = args.get("methods", ["crt_sh"])
    results: list[str] = []

    if "crt_sh" in methods:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%25.{target}&output=json")
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub and sub not in results:
                                results.append(sub)
        except Exception:
            pass

    if "subfinder" in methods and shutil.which("subfinder"):
        out = await _run_process(["subfinder", "-d", target, "-silent"], timeout=30)
        for line in out.strip().split("\n"):
            line = line.strip()
            if line and line not in results:
                results.append(line)

    return {"target": target, "subdomains": sorted(set(results)), "count": len(set(results))}


async def port_scan(args: dict) -> dict:
    target = args["target"]
    ports = args.get("ports", "top100")

    if shutil.which("nmap"):
        cmd = ["nmap", "-sT", "--top-ports", "100", "-T4", "--open", "-oG", "-", target]
        out = await _run_process(cmd, timeout=60)
        open_ports = []
        for line in out.split("\n"):
            if "Ports:" in line:
                parts = line.split("Ports:")[1].strip()
                for port_info in parts.split(","):
                    port_info = port_info.strip()
                    if "/open/" in port_info:
                        port_num = port_info.split("/")[0].strip()
                        open_ports.append(int(port_num))
        return {"target": target, "open_ports": open_ports, "count": len(open_ports)}

    return {"target": target, "open_ports": [], "message": "nmap not installed"}


async def tech_fingerprint(args: dict) -> dict:
    urls = args["urls"]
    results = {}

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        for url in urls[:20]:
            if not url.startswith("http"):
                url = f"https://{url}"
            try:
                resp = await client.get(url)
                tech: dict[str, Any] = {"status": resp.status_code}
                h = resp.headers
                if "server" in h:
                    tech["server"] = h["server"]
                if "x-powered-by" in h:
                    tech["powered_by"] = h["x-powered-by"]
                if "x-jenkins" in h:
                    tech["jenkins"] = h["x-jenkins"]

                body_lower = resp.text[:10000].lower()
                if "laravel_session" in (h.get("set-cookie", "")):
                    tech["framework"] = "Laravel"
                if "wp-content" in body_lower:
                    tech["cms"] = "WordPress"
                if "joomla" in body_lower:
                    tech["cms"] = "Joomla"
                if "x-drupal" in h:
                    tech["cms"] = "Drupal"

                for waf_name, waf_sig in [
                    ("Cloudflare", "cf-ray"),
                    ("AWS WAF", "x-amzn-requestid"),
                    ("Akamai", "x-akamai-transformed"),
                ]:
                    if waf_sig in h:
                        tech["waf"] = waf_name

                results[url] = tech
            except Exception as exc:
                results[url] = {"error": str(exc)}

    return {"technologies": results}


async def param_discovery(args: dict) -> dict:
    target = args["target"]
    results: list[str] = []

    if shutil.which("paramspider"):
        out = await _run_process(["paramspider", "-d", target, "--quiet"], timeout=45)
        for line in out.strip().split("\n"):
            line = line.strip()
            if line and "?" in line:
                results.append(line)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey&limit=200"
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:
                    url = row[0]
                    if "?" in url and url not in results:
                        results.append(url)
    except Exception:
        pass

    return {"target": target, "urls_with_params": results[:500], "count": len(results)}


async def js_analysis(args: dict) -> dict:
    urls = args["urls"]
    findings: dict[str, list[str]] = {"endpoints": [], "secrets": []}

    import re
    endpoint_pattern = re.compile(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']')
    secret_patterns = [
        re.compile(r'(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
    ]

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for url in urls[:10]:
            try:
                resp = await client.get(url)
                text = resp.text
                for match in endpoint_pattern.findall(text):
                    if match not in findings["endpoints"]:
                        findings["endpoints"].append(match)
                for pat in secret_patterns:
                    for match in pat.findall(text):
                        findings["secrets"].append(f"{url}: {match[:20]}...")
            except Exception:
                continue

    return findings


async def load_knowledge_tool(args: dict) -> dict:
    category = args["category"]
    return load_category(category)


async def vuln_scan_tool(args: dict) -> dict:
    """Route to the appropriate scanner based on scan_type."""
    scan_type = args["scan_type"]
    url = args["url"]
    params = args.get("params")
    method = args.get("method", "GET")
    headers = args.get("headers")
    custom_payloads = args.get("payloads")

    if scan_type == "xss":
        from backend.tools.scanners.xss import scan_xss
        results = await scan_xss(url, params=params, method=method, headers=headers, payloads=custom_payloads)
    elif scan_type == "sqli":
        from backend.tools.scanners.sqli import scan_sqli
        results = await scan_sqli(url, params=params, method=method, headers=headers, payloads=custom_payloads)
    elif scan_type == "ssrf":
        from backend.tools.scanners.ssrf import scan_ssrf
        results = await scan_ssrf(url, params=params, method=method, headers=headers)
    elif scan_type == "lfi":
        from backend.tools.scanners.lfi_rfi import scan_lfi
        results = await scan_lfi(url, params=params, method=method, headers=headers)
    elif scan_type == "nosqli":
        from backend.tools.scanners.nosqli import scan_nosqli
        results = await scan_nosqli(url, params=params, method=method, headers=headers)
    elif scan_type == "idor":
        from backend.tools.scanners.idor import scan_idor
        results = await scan_idor(url, method=method, headers=headers)
    elif scan_type == "ssti":
        from backend.tools.scanners.ssti import scan_ssti
        results = await scan_ssti(url, params=params, method=method, headers=headers)
    elif scan_type == "crlf":
        from backend.tools.scanners.crlf import scan_crlf
        results = await scan_crlf(url, params=params, method=method, headers=headers)
    elif scan_type == "host_header":
        from backend.tools.scanners.host_header import scan_host_header
        results = await scan_host_header(url, headers=headers)
    else:
        kb = get_payloads_for_vuln(scan_type)
        payloads = custom_payloads or kb.get("payloads", [])[:10]
        results = {
            "scan_type": scan_type,
            "url": url,
            "payloads_available": len(payloads),
            "status": "scanner_stub",
            "message": f"Dedicated scanner for '{scan_type}' uses knowledge-base payloads.",
        }

    return {"scan_type": scan_type, "url": url, "findings": results if isinstance(results, list) else [], "raw": results}


TOOL_REGISTRY: dict[str, Any] = {
    "subdomain_enum": subdomain_enum,
    "port_scan": port_scan,
    "tech_fingerprint": tech_fingerprint,
    "http_request": _http_request,
    "param_discovery": param_discovery,
    "js_analysis": js_analysis,
    "load_knowledge": load_knowledge_tool,
    "vuln_scan": vuln_scan_tool,
    "nuclei_scan": lambda args: {"status": "not_yet_implemented", "tool": "nuclei_scan"},
    "tech_cve_test": lambda args: {"status": "not_yet_implemented", "tool": "tech_cve_test"},
    "bypass_test": lambda args: {"status": "not_yet_implemented", "tool": "bypass_test"},
    "verify_finding": lambda args: {"status": "not_yet_implemented", "tool": "verify_finding"},
}


async def execute_tool(tool_name: str, args: dict) -> Any:
    """Execute a registered tool by name."""
    handler = TOOL_REGISTRY.get(tool_name)
    if not handler:
        return {"error": f"Unknown tool: {tool_name}"}
    result = handler(args)
    if asyncio.iscoroutine(result):
        return await result
    return result
