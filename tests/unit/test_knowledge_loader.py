"""Tests for knowledge base loader."""
import pytest
from backend.knowledge.loader import (
    load_category,
    get_payloads_for_vuln,
    get_waf_bypass_payloads,
    clear_cache,
)


@pytest.fixture(autouse=True)
def fresh_cache():
    clear_cache()
    yield
    clear_cache()


def test_load_xss_category():
    data = load_category("xss")
    assert data["id"] == "xss"
    assert "payloads" in data
    assert len(data["payloads"]["basic"]) > 0


def test_load_sqli_category():
    data = load_category("sqli")
    assert data["id"] == "sqli"
    assert "error_based" in data["payloads"]


def test_load_ssrf_category():
    data = load_category("ssrf")
    assert data["id"] == "ssrf"
    assert "cloud_metadata" in data["payloads"]
    assert "aws" in data["payloads"]["cloud_metadata"]


def test_load_lfi_category():
    data = load_category("lfi")
    assert data["id"] == "lfi"
    assert any("etc/passwd" in p for p in data["payloads"]["basic"])


def test_load_nosqli_category():
    data = load_category("nosqli")
    assert data["id"] == "nosqli"
    assert len(data["payloads"]["auth_bypass"]) > 0


def test_load_laravel_profile():
    data = load_category("laravel")
    assert data["id"] == "laravel"
    assert "/.env" in data["sensitive_paths"]
    assert "CVE-2021-3129" in data["cves"]


def test_load_wordpress_profile():
    data = load_category("wordpress")
    assert data["id"] == "wordpress"
    assert "/wp-login.php" in data["detection"]["paths"]


def test_load_jenkins_profile():
    data = load_category("jenkins")
    assert data["id"] == "jenkins"
    assert data["default_credentials"][0]["username"] == "admin"


def test_load_bypass_403():
    data = load_category("bypass_403")
    assert data["id"] == "bypass_403"
    assert len(data["techniques"]["path_manipulation"]) > 5


def test_load_bypass_waf():
    data = load_category("bypass_waf")
    assert "wafs" in data
    assert "cloudflare" in data["wafs"]
    assert len(data["wafs"]["cloudflare"]["payloads"]) > 0


def test_load_google_dorks():
    data = load_category("google_dorks")
    assert data["id"] == "google_dorks"
    assert "dorks" in data
    assert len(data["dorks"]["secrets"]) > 0


def test_load_unknown_category():
    data = load_category("nonexistent_category")
    assert "error" in data


def test_get_payloads_for_xss():
    result = get_payloads_for_vuln("xss")
    assert "payloads" in result
    assert len(result["payloads"]) > 0


def test_get_payloads_with_waf():
    result = get_payloads_for_vuln("xss", waf="cloudflare")
    assert "waf_bypass_payloads" in result
    assert len(result["waf_bypass_payloads"]) > 0


def test_get_waf_bypass():
    payloads = get_waf_bypass_payloads("cloudflare")
    assert len(payloads) > 0


def test_load_exposed_source():
    data = load_category("exposed_source")
    assert data["id"] == "exposed_source"
    assert "git" in data["paths"]


def test_load_default_creds():
    data = load_category("default_creds")
    assert data["id"] == "default_creds"
    assert "grafana" in data["credentials"]
