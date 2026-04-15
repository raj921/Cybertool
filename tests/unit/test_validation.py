"""Tests for validation, PoC generation, and reporting."""
import json
import pytest

from backend.tools.validators.poc_gen import generate_poc
from backend.reporting.generator import generate_markdown_report, generate_json_report, generate_html_report
from backend.reporting.severity import estimate_cvss, get_severity


def test_generate_poc_curl():
    poc = generate_poc(
        finding_type="xss",
        url="https://example.com/search?q=<script>alert(1)</script>",
        payload="<script>alert(1)</script>",
    )
    assert "curl" in poc["curl_command"]
    assert "example.com" in poc["curl_command"]
    assert poc["type"] == "xss"


def test_generate_poc_with_headers():
    poc = generate_poc(
        finding_type="host_header",
        url="https://example.com/",
        payload="evil.com",
        headers={"X-Forwarded-Host": "evil.com"},
    )
    assert "X-Forwarded-Host" in poc["curl_command"]
    assert "X-Forwarded-Host" in poc["http_request"]


def test_generate_poc_post():
    poc = generate_poc(
        finding_type="sqli",
        url="https://example.com/login",
        payload="' OR 1=1--",
        method="POST",
        body="username=admin&password=' OR 1=1--",
    )
    assert "-X POST" in poc["curl_command"]
    assert "requests.post" in poc["python_script"]


def test_generate_markdown_report():
    findings = [
        {"type": "xss", "severity": "high", "title": "XSS on /search", "url": "https://t.com/search", "confidence": 92, "payload": "<script>alert(1)</script>"},
        {"type": "sqli", "severity": "critical", "title": "SQLi on /login", "url": "https://t.com/login", "confidence": 95},
    ]
    report = generate_markdown_report("t.com", findings)
    assert "CyberHunter Security Report" in report
    assert "CRITICAL" in report
    assert "HIGH" in report
    assert "t.com" in report
    assert "SQLi on /login" in report
    # Critical should come first
    assert report.index("CRITICAL") < report.index("HIGH")


def test_generate_json_report():
    findings = [{"type": "xss", "severity": "medium", "title": "Test", "url": "https://t.com", "confidence": 80}]
    report_str = generate_json_report("t.com", findings)
    report = json.loads(report_str)
    assert report["target"] == "t.com"
    assert report["total_findings"] == 1
    assert len(report["findings"]) == 1


def test_generate_html_report():
    findings = [{"type": "xss", "severity": "medium", "title": "Test"}]
    html = generate_html_report("t.com", findings)
    assert "<html" in html
    assert "CyberHunter" in html


def test_cvss_scoring():
    assert estimate_cvss("sqli", 100.0) == 9.5
    assert estimate_cvss("xss", 80.0) == 4.4
    assert estimate_cvss("open_redirect", 90.0) == 2.2


def test_severity_mapping():
    assert get_severity("sqli") == "critical"
    assert get_severity("xss") == "medium"
    assert get_severity("idor") == "high"
    assert get_severity("unknown_type") == "medium"


def test_empty_report():
    report = generate_markdown_report("t.com", [])
    assert "CyberHunter" in report
    assert "Findings:** 0" in report
