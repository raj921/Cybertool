"""Async tool executor -- maps tool names to implementations and runs them."""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
from typing import Any

import httpx

from backend.knowledge.loader import load_category, get_payloads_for_vuln


async def _run_process(cmd: list[str], timeout: int = 60) -> dict:
    """Run an external process asynchronously.

    Returns `{ok: True, stdout: str}` on success, or `{ok: False, error: str}`
    on failure. Callers should inspect `ok` before using stdout so that a
    timeout error does not accidentally get parsed as tool output.
    """
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"ok": True, "stdout": stdout.decode(errors="replace")}
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        return {"ok": False, "error": f"Command timed out after {timeout}s"}
    except FileNotFoundError:
        return {"ok": False, "error": f"Tool not found: {cmd[0]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


DNS_BRUTE_WORDLIST: tuple[str, ...] = (
    "www", "mail", "api", "dev", "staging", "test", "admin", "portal",
    "app", "shop", "blog", "support", "help", "docs", "cdn", "static",
    "img", "images", "assets", "media", "files", "download", "uploads",
    "auth", "login", "signin", "sso", "oauth", "account", "accounts",
    "dashboard", "panel", "console", "manage", "beta", "alpha", "demo",
    "preview", "sandbox", "qa", "uat", "prod", "production", "internal",
    "intranet", "vpn", "mx", "ns", "ns1", "ns2", "smtp", "pop", "imap",
    "ftp", "git", "gitlab", "jenkins", "jira", "confluence", "wiki",
    "webmail", "secure", "ssl", "m", "mobile", "mdm", "ldap", "monitor",
    "metrics", "graphs", "grafana", "kibana", "elastic", "redis", "db",
    "database", "sql", "postgres", "mysql", "mongo", "s3", "storage",
)


async def _dns_resolve(host: str) -> bool:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, socket.gethostbyname, host)
        return True
    except (socket.gaierror, socket.herror, UnicodeError):
        return False


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
    methods = args.get("methods", ["crt_sh", "dns_brute"])
    results: set[str] = set()
    errors: list[str] = []

    if "crt_sh" in methods:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%25.{target}&output=json")
                if resp.status_code == 200:
                    for entry in resp.json():
                        for sub in (entry.get("name_value", "") or "").split("\n"):
                            sub = sub.strip().lstrip("*.").lower()
                            if sub and sub.endswith(target) and sub != target:
                                results.add(sub)
        except Exception as exc:
            errors.append(f"crt_sh: {exc}")

    if "subfinder" in methods:
        if shutil.which("subfinder"):
            out = await _run_process(["subfinder", "-d", target, "-silent"], timeout=30)
            if out["ok"]:
                for line in out["stdout"].strip().split("\n"):
                    line = line.strip().lower()
                    if line:
                        results.add(line)
            else:
                errors.append(f"subfinder: {out['error']}")
        else:
            errors.append("subfinder: not installed")

    if "dns_brute" in methods:
        async def check(prefix: str) -> str | None:
            host = f"{prefix}.{target}"
            if await _dns_resolve(host):
                return host
            return None

        tasks = [check(p) for p in DNS_BRUTE_WORDLIST]
        found = await asyncio.gather(*tasks, return_exceptions=True)
        for host in found:
            if isinstance(host, str):
                results.add(host)

    return {
        "target": target,
        "subdomains": sorted(results),
        "count": len(results),
        "methods": methods,
        "errors": errors or None,
    }


async def port_scan(args: dict) -> dict:
    target = args["target"]
    ports = args.get("ports", "top100")

    if shutil.which("nmap"):
        cmd = ["nmap", "-sT", "--top-ports", "100", "-T4", "--open", "-oG", "-", target]
        out = await _run_process(cmd, timeout=60)
        if not out["ok"]:
            return {"target": target, "open_ports": [], "error": out["error"]}
        open_ports: list[int] = []
        for line in out["stdout"].split("\n"):
            if "Ports:" in line:
                parts = line.split("Ports:")[1].strip()
                for port_info in parts.split(","):
                    port_info = port_info.strip()
                    if "/open/" in port_info:
                        port_num = port_info.split("/")[0].strip()
                        try:
                            open_ports.append(int(port_num))
                        except ValueError:
                            pass
        return {"target": target, "open_ports": open_ports, "count": len(open_ports)}

    return await _async_port_scan(target, ports)


_TOP_TCP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 1723, 2049, 2375, 3000, 3001, 3306, 3389, 4000,
    5000, 5432, 5601, 5900, 5984, 6379, 6443, 7001, 7474, 7687, 8000,
    8008, 8080, 8081, 8088, 8090, 8443, 8500, 8501, 8888, 9000, 9042,
    9090, 9092, 9200, 9300, 9418, 9443, 10000, 11211, 15672, 15673,
    27017, 27018, 50070, 50075, 50090,
)


async def _async_port_scan(target: str, ports: str = "top100") -> dict:
    """Fallback port scanner using asyncio TCP connects (no nmap required)."""
    port_list: list[int] = list(_TOP_TCP_PORTS)
    if isinstance(ports, str) and "-" in ports:
        try:
            lo, hi = ports.split("-", 1)
            port_list = list(range(max(1, int(lo)), min(65535, int(hi)) + 1))
        except Exception:
            pass

    async def probe(port: int) -> int | None:
        try:
            fut = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(fut, timeout=1.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None

    sem = asyncio.Semaphore(64)

    async def bounded(p: int) -> int | None:
        async with sem:
            return await probe(p)

    results = await asyncio.gather(*(bounded(p) for p in port_list))
    open_ports = sorted(p for p in results if p is not None)
    return {
        "target": target,
        "open_ports": open_ports,
        "count": len(open_ports),
        "method": "async_tcp_connect",
    }


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
        if out["ok"]:
            for line in out["stdout"].strip().split("\n"):
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


async def verify_finding_tool(args: dict) -> dict:
    """Run the 5-layer verifier on a candidate finding."""
    from backend.tools.validators.verifier import verify_finding as _verify
    return await _verify(
        finding_type=args["finding_type"],
        url=args["url"],
        payload=args.get("payload", ""),
        method=args.get("method", "GET"),
        headers=args.get("headers"),
        original_response=args.get("original_response"),
    )


async def tech_cve_test_tool(args: dict) -> dict:
    """Apply tech-profile CVE probes from the knowledge base and report what matches."""
    url = args["url"]
    tech = (args.get("technology") or "").lower()
    version = args.get("version")

    profile = load_category(tech)
    if "error" in profile:
        return {"url": url, "technology": tech, "error": profile["error"]}

    probes = []
    for path in (profile.get("paths") or [])[:15]:
        probes.append({"kind": "path", "path": path})
    for cve in (profile.get("cves") or [])[:10]:
        probes.append({"kind": "cve", "cve": cve})

    hits: list[dict] = []
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        for p in probes:
            if p["kind"] != "path":
                continue
            test_url = url.rstrip("/") + "/" + str(p["path"]).lstrip("/")
            try:
                resp = await client.get(test_url)
                if resp.status_code in (200, 301, 302, 401, 403):
                    hits.append({
                        "url": test_url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type"),
                        "length": len(resp.text),
                    })
            except Exception:
                continue

    return {
        "url": url,
        "technology": tech,
        "version": version,
        "probes_run": len(probes),
        "interesting_hits": hits,
        "cve_reference": [p["cve"] for p in probes if p["kind"] == "cve"],
    }


async def bypass_test_tool(args: dict) -> dict:
    """Try common bypass techniques for 403/429/waf against a URL using the knowledge base."""
    bypass_type = args.get("bypass_type", "403")
    url = args["url"]

    playbook_map = {
        "403": "bypass_403",
        "waf": "bypass_waf",
        "429": "bypass_429",
        "2fa": "bypass_2fa",
        "captcha": "bypass_captcha",
    }
    playbook = load_category(playbook_map.get(bypass_type, "bypass_403"))

    attempts: list[dict] = []
    header_variants: list[dict] = []
    if isinstance(playbook, dict):
        for h in (playbook.get("headers") or [])[:20]:
            if isinstance(h, dict):
                header_variants.append(h)
            elif isinstance(h, str) and ":" in h:
                k, v = h.split(":", 1)
                header_variants.append({k.strip(): v.strip()})

    if not header_variants:
        header_variants = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "localhost"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        try:
            baseline = await client.get(url)
            baseline_status = baseline.status_code
        except Exception as exc:
            return {"url": url, "bypass_type": bypass_type, "error": f"baseline failed: {exc}"}

        for variant in header_variants:
            try:
                r = await client.get(url, headers=variant)
                attempts.append({
                    "headers": variant,
                    "status": r.status_code,
                    "bypassed": r.status_code != baseline_status and r.status_code < 400,
                    "length": len(r.text),
                })
            except Exception:
                continue

    successes = [a for a in attempts if a["bypassed"]]
    return {
        "url": url,
        "bypass_type": bypass_type,
        "baseline_status": baseline_status,
        "attempts": len(attempts),
        "successes": successes,
        "playbook_used": playbook_map.get(bypass_type, "bypass_403"),
    }


async def nuclei_scan_tool(args: dict) -> dict:
    """Run nuclei if installed, otherwise fall back to a knowledge-driven probe set."""
    target = args["target"]
    templates = args.get("templates", [])
    severity = args.get("severity") or ["critical", "high", "medium"]

    if shutil.which("nuclei"):
        cmd = ["nuclei", "-u", target, "-silent", "-jsonl", "-severity", ",".join(severity)]
        if templates:
            cmd += ["-t", ",".join(templates)]
        out = await _run_process(cmd, timeout=120)
        if not out["ok"]:
            return {"target": target, "error": out["error"], "findings": []}
        findings = []
        for line in out["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"target": target, "tool": "nuclei", "findings": findings, "count": len(findings)}

    return {
        "target": target,
        "tool": "nuclei",
        "installed": False,
        "message": "nuclei not installed; use tech_cve_test, vuln_scan, or http_request instead.",
    }


TOOL_REGISTRY: dict[str, Any] = {
    "subdomain_enum": subdomain_enum,
    "port_scan": port_scan,
    "tech_fingerprint": tech_fingerprint,
    "http_request": _http_request,
    "param_discovery": param_discovery,
    "js_analysis": js_analysis,
    "load_knowledge": load_knowledge_tool,
    "vuln_scan": vuln_scan_tool,
    "nuclei_scan": nuclei_scan_tool,
    "tech_cve_test": tech_cve_test_tool,
    "bypass_test": bypass_test_tool,
    "verify_finding": verify_finding_tool,
}


async def execute_tool(tool_name: str, args: dict) -> Any:
    """Execute a registered tool by name."""
    handler = TOOL_REGISTRY.get(tool_name)
    if not handler:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        result = handler(args)
        if asyncio.iscoroutine(result):
            return await result
        return result
    except Exception as exc:
        return {"error": f"{tool_name} crashed: {exc}"}
