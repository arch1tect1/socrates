"""Unit tests for IOCExtractor."""

from __future__ import annotations

import pytest

from backend.services.ioc_extractor import IOCExtractor, refang


@pytest.fixture
def ex() -> IOCExtractor:
    return IOCExtractor(domain_whitelist=frozenset({"microsoft.com", "google.com"}))


def test_ipv4_public_kept(ex: IOCExtractor) -> None:
    r = ex.extract("connect from 8.8.8.8 to host")
    ips = [x.ioc_value for x in r if x.ioc_type == "ip"]
    assert "8.8.8.8" in ips


def test_ipv4_private_filtered(ex: IOCExtractor) -> None:
    r = ex.extract("10.0.0.5 and 192.168.1.1 and 172.16.0.1 and 185.1.1.1")
    ips = [x.ioc_value for x in r if x.ioc_type == "ip"]
    assert "185.1.1.1" in ips
    assert "10.0.0.5" not in ips
    assert "192.168.1.1" not in ips


def test_defang_ip(ex: IOCExtractor) -> None:
    r = ex.extract("C2 at 8[.]8[.]8[.]8")
    assert any(x.ioc_value == "8.8.8.8" for x in r if x.ioc_type == "ip")


def test_defang_url(ex: IOCExtractor) -> None:
    r = ex.extract("hxxp://evil.example/phish")
    urls = [x.ioc_value for x in r if x.ioc_type == "url"]
    assert any("http://evil.example" in u for u in urls)


def test_dedupe(ex: IOCExtractor) -> None:
    r = ex.extract("8.8.8.8 8.8.8.8 8.8.8.8")
    ips = [x for x in r if x.ioc_type == "ip"]
    assert len(ips) == 1


def test_hash_lengths(ex: IOCExtractor) -> None:
    md5 = "a" * 32
    sha1 = "b" * 40
    sha256 = "c" * 64
    r = ex.extract(f"{md5} {sha1} {sha256}")
    types = {x.ioc_type: x.ioc_value for x in r}
    assert types.get("hash_md5") == md5.lower()
    assert types.get("hash_sha1") == sha1.lower()
    assert types.get("hash_sha256") == sha256.lower()


def test_domain_whitelist(ex: IOCExtractor) -> None:
    r = ex.extract("login.microsoft.com and evil.com")
    doms = [x.ioc_value for x in r if x.ioc_type == "domain"]
    assert "evil.com" in doms
    assert not any("microsoft.com" in d for d in doms)


def test_extract_from_dict(ex: IOCExtractor) -> None:
    # Use globally routable IPs (203.0.113/24 etc. are documentation-reserved and filtered)
    data = {"nested": {"ip": "1.1.1.1"}, "log": "see 8.8.8.8"}
    r = ex.extract_from_dict(data)
    ips = [x.ioc_value for x in r if x.ioc_type == "ip"]
    assert "1.1.1.1" in ips
    assert "8.8.8.8" in ips


def test_refang_email() -> None:
    assert "user@test.com" in refang("user[at]test.com")


def test_wazuh_fixture_extracts_public_srcip(ex: IOCExtractor) -> None:
    import json
    from pathlib import Path

    p = Path(__file__).parent / "fixtures" / "wazuh_ssh_bruteforce.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    blob = json.dumps(payload, ensure_ascii=False)
    r = ex.extract(blob) + ex.extract_from_dict(payload)
    values = {(x.ioc_type, x.ioc_value) for x in r}
    assert ("ip", "185.234.217.42") in values
