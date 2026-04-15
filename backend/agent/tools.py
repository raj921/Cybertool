"""Tool definitions registered with the LLM for autonomous invocation.

Each tool is an OpenAI-compatible function definition dict.
The agent engine maps tool names to actual Python callables at runtime.
"""
from __future__ import annotations

TOOL_DEFINITIONS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "subdomain_enum",
            "description": "Enumerate subdomains for a target domain using multiple sources (subfinder, crt.sh, DNS brute). Returns a list of discovered subdomains.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Root domain to enumerate (e.g. example.com)"},
                    "methods": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["subfinder", "crt_sh", "dns_brute"]},
                        "description": "Which enumeration methods to use. Defaults to all.",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "port_scan",
            "description": "Scan open ports and identify running services on a target host.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Host or IP to scan"},
                    "ports": {"type": "string", "description": "Port range (e.g. '1-1000' or 'top100'). Default: top100"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tech_fingerprint",
            "description": "Detect technologies, frameworks, web servers, WAFs running on one or more URLs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of URLs to fingerprint",
                    },
                },
                "required": ["urls"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a raw HTTP request and return status, headers, and body. Use for manual probing, .env checks, sensitive-file discovery, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"], "default": "GET"},
                    "headers": {"type": "object", "description": "Custom headers dict"},
                    "body": {"type": "string", "description": "Request body"},
                    "follow_redirects": {"type": "boolean", "default": True},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "param_discovery",
            "description": "Discover URL parameters and endpoints for a target using paramspider, wayback URLs, and crawling.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain or URL"},
                    "methods": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["paramspider", "wayback", "crawl"]},
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "js_analysis",
            "description": "Analyze JavaScript files for endpoints, API keys, secrets, and interesting patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "URLs of JS files to analyze",
                    },
                },
                "required": ["urls"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vuln_scan",
            "description": "Run a specific vulnerability scanner against a target URL with optional payloads from the knowledge base.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_type": {
                        "type": "string",
                        "enum": [
                            "xss", "sqli", "ssrf", "nosqli", "lfi", "rfi", "idor",
                            "ssti", "crlf", "csrf", "host_header", "file_upload",
                            "oauth", "jwt", "cache_poison", "race_condition",
                            "open_redirect", "cors", "xxe",
                        ],
                    },
                    "url": {"type": "string", "description": "Target URL or endpoint"},
                    "params": {"type": "object", "description": "Parameters to test"},
                    "payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Custom payloads. If empty, uses knowledge-base defaults.",
                    },
                    "headers": {"type": "object", "description": "Custom headers"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                },
                "required": ["scan_type", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nuclei_scan",
            "description": "Run Nuclei templates against a target. Can use built-in, custom, or AI-generated templates.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "templates": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Template IDs or paths. Empty = auto-select based on tech.",
                    },
                    "severity": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tech_cve_test",
            "description": "Test technology-specific CVE payloads from the knowledge base (e.g., Laravel Ignition RCE, Jira SSRF, Jenkins Groovy RCE).",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "technology": {"type": "string", "description": "Detected technology name (e.g. 'laravel', 'jenkins', 'jira')"},
                    "version": {"type": "string", "description": "Detected version if known"},
                },
                "required": ["url", "technology"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bypass_test",
            "description": "Run bypass techniques (403, 2FA, rate-limit 429, captcha) against a target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "bypass_type": {"type": "string", "enum": ["403", "2fa", "429", "captcha", "waf"]},
                    "url": {"type": "string"},
                    "original_request": {"type": "object", "description": "The original request that was blocked"},
                },
                "required": ["bypass_type", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_finding",
            "description": "Run multi-pass verification on a potential finding to confirm it is real (not a false positive). Returns confidence score.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_type": {"type": "string"},
                    "url": {"type": "string"},
                    "payload": {"type": "string"},
                    "original_response": {"type": "string", "description": "The response that triggered the finding"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object"},
                },
                "required": ["finding_type", "url", "payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "load_knowledge",
            "description": "Load attack knowledge from the built-in knowledge base for a specific category.",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": [
                            "xss", "sqli", "ssrf", "nosqli", "lfi", "rfi", "idor",
                            "ssti", "crlf", "csrf", "host_header", "file_upload",
                            "oauth", "jwt", "cache_poison", "mass_assignment",
                            "open_redirect", "dos", "deserialization", "ssi",
                            "bypass_403", "bypass_2fa", "bypass_429", "bypass_captcha", "bypass_waf",
                            "wordpress", "jenkins", "jira", "nginx", "laravel",
                            "grafana", "confluence", "apache", "haproxy",
                            "account_takeover", "business_logic", "forgot_password",
                            "default_creds", "exposed_source", "api_keys",
                            "google_dorks", "shodan_dorks", "github_dorks",
                        ],
                    },
                },
                "required": ["category"],
            },
        },
    },
]
