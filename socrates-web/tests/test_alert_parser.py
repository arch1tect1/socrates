"""Parser registry smoke tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.services.alert_parser import ParserRegistry, WazuhParser


def test_wazuh_parser_accepts_fixture() -> None:
    p = Path(__file__).parent / "fixtures" / "wazuh_ssh_bruteforce.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    wp = WazuhParser()
    assert wp.can_parse(payload)
    ac = wp.parse(payload)
    assert ac.source.startswith("wazuh:")
    assert ac.severity == "high"
    assert "185.234.217.42" in (ac.description or "") or "185.234.217.42" in json.dumps(ac.raw_payload)


def test_registry_wazuh_hint() -> None:
    p = Path(__file__).parent / "fixtures" / "wazuh_ssh_bruteforce.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    reg = ParserRegistry()
    ac = reg.parse(payload, parser_hint="wazuh")
    assert ac.title
