"""Helpers for analyst feedback on decisions."""

from __future__ import annotations

from .models import DecisionRecord
from .store import load_decision, save_decision


def update_feedback(
    data_dir,
    chat_id: int,
    decision_id: str,
    *,
    feedback: str | None = None,
    note: str | None = None,
    action_taken: str | None = None,
) -> DecisionRecord | None:
    rec = load_decision(data_dir, chat_id, decision_id)
    if not rec:
        return None
    if feedback is not None:
        rec.analyst_feedback = feedback
    if note is not None:
        rec.analyst_note = note
    if action_taken is not None:
        rec.analyst_action_taken = action_taken
    save_decision(data_dir, rec)
    return rec


def create_decision_record(
    *,
    decision_id: str,
    chat_id: int,
    ioc_type: str,
    ioc_value: str,
    enrichment_summary: dict,
    ambiguity_flags: list[str],
    llm_response: str,
    ai_verdict: str,
    ai_severity: str,
) -> DecisionRecord:
    from .store import utc_now_iso

    return DecisionRecord(
        id=decision_id,
        chat_id=chat_id,
        timestamp=utc_now_iso(),
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        enrichment_summary=enrichment_summary,
        ambiguity_flags=ambiguity_flags,
        llm_response=llm_response,
        ai_verdict=ai_verdict,
        ai_severity=ai_severity,
    )
