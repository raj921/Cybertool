"""Knowledge base loader. Reads YAML playbooks and injects them into agent context."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from backend.config import settings

_cache: dict[str, Any] = {}


def _knowledge_path() -> Path:
    return settings.knowledge_dir


def load_yaml(relative_path: str) -> dict | list:
    """Load a YAML file from the knowledge directory, with caching."""
    if relative_path in _cache:
        return _cache[relative_path]
    full = _knowledge_path() / relative_path
    if not full.exists():
        return {}
    with open(full) as f:
        data = yaml.safe_load(f) or {}
    _cache[relative_path] = data
    return data


def load_category(category: str) -> dict:
    """Load a knowledge category by name. Maps category names to YAML files."""
    CATEGORY_MAP: dict[str, str] = {
        # Vulnerabilities
        "xss": "vulns/xss.yaml",
        "sqli": "vulns/sqli.yaml",
        "ssrf": "vulns/ssrf.yaml",
        "nosqli": "vulns/nosqli.yaml",
        "lfi": "vulns/lfi.yaml",
        "rfi": "vulns/rfi.yaml",
        "idor": "vulns/idor.yaml",
        "ssti": "vulns/ssti.yaml",
        "crlf": "vulns/crlf.yaml",
        "csrf": "vulns/csrf.yaml",
        "host_header": "vulns/host_header.yaml",
        "file_upload": "vulns/file_upload.yaml",
        "oauth": "vulns/oauth.yaml",
        "jwt": "vulns/jwt.yaml",
        "cache_poison": "vulns/cache_poison.yaml",
        "mass_assignment": "vulns/mass_assignment.yaml",
        "open_redirect": "vulns/open_redirect.yaml",
        "dos": "vulns/dos.yaml",
        "deserialization": "vulns/deserialization.yaml",
        "ssi": "vulns/ssi.yaml",
        # Bypasses
        "bypass_403": "bypasses/bypass_403.yaml",
        "bypass_2fa": "bypasses/bypass_2fa.yaml",
        "bypass_429": "bypasses/bypass_429.yaml",
        "bypass_captcha": "bypasses/bypass_captcha.yaml",
        "bypass_waf": "bypasses/bypass_waf.yaml",
        # Tech profiles
        "wordpress": "techprofiles/wordpress.yaml",
        "jenkins": "techprofiles/jenkins.yaml",
        "jira": "techprofiles/jira.yaml",
        "nginx": "techprofiles/nginx.yaml",
        "laravel": "techprofiles/laravel.yaml",
        "grafana": "techprofiles/grafana.yaml",
        "confluence": "techprofiles/confluence.yaml",
        "apache": "techprofiles/apache.yaml",
        "haproxy": "techprofiles/haproxy.yaml",
        # Misc
        "account_takeover": "misc/account_takeover.yaml",
        "business_logic": "misc/business_logic.yaml",
        "forgot_password": "misc/forgot_password.yaml",
        "default_creds": "misc/default_creds.yaml",
        "exposed_source": "misc/exposed_source.yaml",
        "api_keys": "misc/api_keys.yaml",
        # Recon
        "google_dorks": "recon/google_dorks.yaml",
        "shodan_dorks": "recon/shodan_dorks.yaml",
        "github_dorks": "recon/github_dorks.yaml",
    }
    path = CATEGORY_MAP.get(category)
    if not path:
        return {"error": f"Unknown category: {category}"}
    data = load_yaml(path)
    if not data:
        return {"category": category, "status": "not_yet_populated", "message": "Knowledge file exists but has no content yet."}
    return data


def get_tech_profile(technology: str) -> dict:
    """Load a technology-specific attack profile."""
    return load_category(technology.lower().replace(" ", "_"))


def get_waf_bypass_payloads(waf_name: str) -> list[str]:
    """Get WAF-specific bypass payloads."""
    data = load_category("bypass_waf")
    if isinstance(data, dict) and "wafs" in data:
        waf_data = data["wafs"].get(waf_name.lower(), {})
        return waf_data.get("payloads", [])
    return []


def get_payloads_for_vuln(vuln_type: str, waf: str | None = None) -> dict:
    """Get payloads for a vulnerability type, optionally filtered by WAF."""
    data = load_category(vuln_type)
    if not isinstance(data, dict):
        return {"payloads": []}
    result = {"payloads": data.get("payloads", {}).get("basic", [])}
    if waf and "payloads" in data and "waf_bypass" in data["payloads"]:
        waf_payloads = data["payloads"]["waf_bypass"].get(waf.lower(), [])
        result["waf_bypass_payloads"] = waf_payloads
    return result


def list_categories() -> list[str]:
    """List all available knowledge categories."""
    from backend.knowledge.loader import load_category
    CATEGORY_MAP = load_category.__code__.co_consts
    return list(load_category.__defaults__ or [])


def clear_cache() -> None:
    _cache.clear()
