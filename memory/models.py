"""Decision record model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class DecisionRecord:
    id: str
    chat_id: int
    timestamp: str
    ioc_type: str
    ioc_value: str
    enrichment_summary: dict[str, Any]
    ambiguity_flags: list[str]
    ai_verdict: str = ""
    ai_severity: str = ""
    ai_recommended_action: str = ""
    analyst_feedback: str = ""
    analyst_action_taken: str = ""
    analyst_note: str = ""
    resolution: str = ""
    tags: list[str] = field(default_factory=list)
    llm_response: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DecisionRecord:
        return cls(
            id=str(d.get("id", "")),
            chat_id=int(d.get("chat_id", 0)),
            timestamp=str(d.get("timestamp", "")),
            ioc_type=str(d.get("ioc_type", "")),
            ioc_value=str(d.get("ioc_value", "")),
            enrichment_summary=dict(d.get("enrichment_summary") or {}),
            ambiguity_flags=list(d.get("ambiguity_flags") or []),
            ai_verdict=str(d.get("ai_verdict", "")),
            ai_severity=str(d.get("ai_severity", "")),
            ai_recommended_action=str(d.get("ai_recommended_action", "")),
            analyst_feedback=str(d.get("analyst_feedback", "")),
            analyst_action_taken=str(d.get("analyst_action_taken", "")),
            analyst_note=str(d.get("analyst_note", "")),
            resolution=str(d.get("resolution", "")),
            tags=list(d.get("tags") or []),
            llm_response=str(d.get("llm_response", "")),
        )
