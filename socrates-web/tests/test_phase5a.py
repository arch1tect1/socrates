"""Phase 5 Part A: status mapping + whitelist helpers."""

from __future__ import annotations

import pytest

from backend.agents.triage_agent import _status_for_verdict
from backend.agents.whitelist_config import is_ioc_whitelisted
from backend.models.alerts import ExtractedIOC


@pytest.mark.parametrize(
    "verdict, conf, expected",
    [
        ("malicious", 0.8, "escalated"),
        ("malicious", 0.74, "investigating"),
        ("benign", 0.9, "resolved"),
        ("benign", 0.84, "investigating"),
        ("suspicious", 0.5, "investigating"),
        ("inconclusive", 0.2, "investigating"),
    ],
)
def test_status_for_verdict(verdict: str, conf: float, expected: str) -> None:
    assert _status_for_verdict(verdict, conf) == expected


def test_whitelist_google_dns() -> None:
    assert is_ioc_whitelisted(ExtractedIOC(ioc_type="ip", ioc_value="8.8.8.8")) is True


def test_whitelist_not_evil_ip() -> None:
    assert is_ioc_whitelisted(ExtractedIOC(ioc_type="ip", ioc_value="185.234.217.42")) is False


def test_whitelist_microsoft_domain() -> None:
    assert is_ioc_whitelisted(ExtractedIOC(ioc_type="domain", ioc_value="www.microsoft.com")) is True
