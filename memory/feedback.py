"""Helpers for analyst feedback on decisions (async + PostgreSQL)."""

from __future__ import annotations

from sqlalchemy import select

from database.engine import get_async_session
from database.models import AnalysisDB, UserDB

from .models import DecisionRecord
from .store import _row_to_record


async def update_feedback(
    telegram_user_id: int,
    decision_id: str,
    *,
    feedback: str | None = None,
    note: str | None = None,
    action_taken: str | None = None,
) -> DecisionRecord | None:
    async with get_async_session() as session:
        result = await session.execute(
            select(AnalysisDB)
            .join(UserDB)
            .where(
                UserDB.telegram_user_id == telegram_user_id,
                AnalysisDB.decision_id == decision_id,
            )
        )
        row = result.scalar_one_or_none()
        if not row:
            return None
        if feedback is not None:
            row.analyst_feedback = feedback
        if note is not None:
            row.analyst_note = note
        if action_taken is not None:
            row.analyst_action_taken = action_taken
        await session.commit()
        await session.refresh(row)
        return _row_to_record(row, telegram_user_id)


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
