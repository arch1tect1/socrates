"""PostgreSQL storage for analyst decisions / analyses (async)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

BAKU_TZ = timezone(timedelta(hours=4))

from sqlalchemy import delete, func, select

from database.crud import get_or_create_user
from database.engine import get_async_session
from database.models import AnalysisDB, UserDB

from .models import DecisionRecord


async def save_decision(record: DecisionRecord) -> None:
    telegram_user_id = record.chat_id
    user_id = await get_or_create_user(telegram_user_id)

    async with get_async_session() as session:
        row = AnalysisDB(
            decision_id=record.id,
            user_id=user_id,
            ioc_type=record.ioc_type,
            ioc_value=record.ioc_value,
            enrichment_data=record.enrichment_summary,
            ambiguity_flags=record.ambiguity_flags,
            ai_verdict=record.ai_verdict,
            ai_severity=record.ai_severity,
            ai_recommended_action=record.ai_recommended_action,
            full_response=record.llm_response,
            analyst_feedback=record.analyst_feedback,
            analyst_action_taken=record.analyst_action_taken,
            analyst_note=record.analyst_note,
            resolution=record.resolution,
            tags=record.tags,
        )
        session.add(row)
        await session.commit()


async def load_decision(telegram_user_id: int, decision_id: str) -> DecisionRecord | None:
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
        return _row_to_record(row, telegram_user_id)


async def load_all_decisions(telegram_user_id: int) -> list[DecisionRecord]:
    async with get_async_session() as session:
        result = await session.execute(
            select(AnalysisDB)
            .join(UserDB)
            .where(UserDB.telegram_user_id == telegram_user_id)
            .order_by(AnalysisDB.created_at.desc())
        )
        rows = result.scalars().all()
        return [_row_to_record(r, telegram_user_id) for r in rows]


async def clear_all_decisions(telegram_user_id: int) -> int:
    async with get_async_session() as session:
        user_result = await session.execute(
            select(UserDB.id).where(UserDB.telegram_user_id == telegram_user_id)
        )
        user_id = user_result.scalar_one_or_none()
        if user_id is None:
            return 0
        result = await session.execute(
            delete(AnalysisDB).where(AnalysisDB.user_id == user_id)
        )
        await session.commit()
        return result.rowcount  # type: ignore[return-value]


def _row_to_record(row: AnalysisDB, telegram_user_id: int) -> DecisionRecord:
    return DecisionRecord(
        id=row.decision_id,
        chat_id=telegram_user_id,
        timestamp=row.created_at.isoformat() if row.created_at else "",
        ioc_type=row.ioc_type or "",
        ioc_value=row.ioc_value or "",
        enrichment_summary=row.enrichment_data or {},
        ambiguity_flags=row.ambiguity_flags or [],
        ai_verdict=row.ai_verdict or "",
        ai_severity=row.ai_severity or "",
        ai_recommended_action=row.ai_recommended_action or "",
        analyst_feedback=row.analyst_feedback or "",
        analyst_action_taken=row.analyst_action_taken or "",
        analyst_note=row.analyst_note or "",
        resolution=row.resolution or "",
        tags=row.tags or [],
        llm_response=row.full_response or "",
    )


# ---------------------------------------------------------------------------
# Utility helpers (unchanged)
# ---------------------------------------------------------------------------

def parse_verdict_lines(llm_text: str) -> tuple[str, str]:
    verdict = ""
    severity = ""
    for line in llm_text.splitlines():
        u = line.upper()
        if "VERDICT:" in u and not verdict:
            m = re.search(r"VERDICT:\s*\[?([^\]\n]+)\]?", line, re.I)
            if m:
                verdict = m.group(1).strip()
        if "SEVERITY:" in u and not severity:
            m = re.search(r"SEVERITY:\s*\[?([^\]\n]+)\]?", line, re.I)
            if m:
                severity = m.group(1).strip()
    return verdict, severity


def utc_now_iso() -> str:
    return datetime.now(BAKU_TZ).strftime("%Y-%m-%dT%H:%M:%S+04:00")
