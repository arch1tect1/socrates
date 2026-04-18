"""Phase 3: triage tool helpers and verdict parsing."""

from __future__ import annotations

import pytest

from backend.agents.tool_executor import tool_ioc_type_to_enrichment
from backend.agents.triage_agent import _parse_verdict_json


@pytest.mark.parametrize(
    "raw, expected_verdict",
    [
        (
            '{"verdict": "malicious", "confidence": 0.9, "reasoning": "x", "recommended_action": "block_ioc"}',
            "malicious",
        ),
        (
            "```json\n"
            '{"verdict": "benign", "confidence": 0.2, "reasoning": "ok", "recommended_action": "close_fp"}\n'
            "```",
            "benign",
        ),
    ],
)
def test_parse_verdict_json_valid(raw: str, expected_verdict: str) -> None:
    out = _parse_verdict_json(raw)
    assert out is not None
    assert out["verdict"] == expected_verdict
    assert 0.0 <= out["confidence"] <= 1.0


def test_parse_verdict_json_invalid() -> None:
    assert _parse_verdict_json("") is None
    assert _parse_verdict_json("not json") is None
    assert _parse_verdict_json('{"verdict": "nope"}') is None


@pytest.mark.parametrize(
    "tool_type, enrichment",
    [
        ("hash_md5", "hash"),
        ("sha256", "hash"),
        ("ip", "ip"),
        ("domain", "domain"),
    ],
)
def test_tool_ioc_type_mapping(tool_type: str, enrichment: str) -> None:
    assert tool_ioc_type_to_enrichment(tool_type) == enrichment
