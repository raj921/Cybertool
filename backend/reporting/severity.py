"""CVSS scoring helper for vulnerability findings."""
from __future__ import annotations

SEVERITY_CVSS = {
    "critical": {"min": 9.0, "max": 10.0, "default": 9.5},
    "high": {"min": 7.0, "max": 8.9, "default": 7.5},
    "medium": {"min": 4.0, "max": 6.9, "default": 5.5},
    "low": {"min": 0.1, "max": 3.9, "default": 2.5},
    "info": {"min": 0.0, "max": 0.0, "default": 0.0},
}

VULN_TYPE_SEVERITY = {
    "sqli": "critical",
    "rce": "critical",
    "deserialization": "critical",
    "ssrf": "high",
    "xss": "medium",
    "idor": "high",
    "lfi": "high",
    "rfi": "critical",
    "ssti": "critical",
    "nosqli": "high",
    "crlf": "medium",
    "csrf": "medium",
    "host_header_injection": "medium",
    "open_redirect": "low",
    "cors": "low",
    "information_disclosure": "low",
}


def estimate_cvss(vuln_type: str, confidence: float = 80.0) -> float:
    severity = VULN_TYPE_SEVERITY.get(vuln_type, "medium")
    base = SEVERITY_CVSS[severity]["default"]
    confidence_factor = confidence / 100.0
    return round(base * confidence_factor, 1)


def get_severity(vuln_type: str) -> str:
    return VULN_TYPE_SEVERITY.get(vuln_type, "medium")
