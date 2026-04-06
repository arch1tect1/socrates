"""Shared database CRUD: user management and admin statistics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

BAKU_TZ = timezone(timedelta(hours=4))

from sqlalchemy import delete, func, select

from .engine import get_async_session
from .models import AnalysisDB, UserDB


async def get_or_create_user(
    telegram_user_id: int,
    username: str | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
    language_code: str | None = None,
) -> int:
    """Upsert a Telegram user. Returns the internal ``users.id``."""
    async with get_async_session() as session:
        result = await session.execute(
            select(UserDB).where(UserDB.telegram_user_id == telegram_user_id)
        )
        user = result.scalar_one_or_none()
        if user:
            user.last_active_at = datetime.now(BAKU_TZ)
            if username is not None:
                user.username = username
            if first_name is not None:
                user.first_name = first_name
            if last_name is not None:
                user.last_name = last_name
            if language_code is not None:
                user.language_code = language_code
            await session.commit()
            return user.id
        user = UserDB(
            telegram_user_id=telegram_user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            language_code=language_code,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user.id


async def update_user_activity(telegram_user_id: int) -> None:
    async with get_async_session() as session:
        result = await session.execute(
            select(UserDB).where(UserDB.telegram_user_id == telegram_user_id)
        )
        user = result.scalar_one_or_none()
        if user:
            user.last_active_at = datetime.now(BAKU_TZ)
            await session.commit()


async def get_user_id(telegram_user_id: int) -> int | None:
    """Resolve ``telegram_user_id`` → ``users.id``.  Returns *None* if unknown."""
    async with get_async_session() as session:
        result = await session.execute(
            select(UserDB.id).where(UserDB.telegram_user_id == telegram_user_id)
        )
        return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Admin statistics
# ---------------------------------------------------------------------------

async def get_admin_stats() -> dict:
    now = datetime.now(BAKU_TZ)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=7)

    async with get_async_session() as session:
        total_users = await session.scalar(select(func.count(UserDB.id))) or 0

        active_users = await session.scalar(
            select(func.count(UserDB.id)).where(UserDB.last_active_at >= week_ago)
        ) or 0

        analyses_today = await session.scalar(
            select(func.count(AnalysisDB.id)).where(AnalysisDB.created_at >= today_start)
        ) or 0

        analyses_week = await session.scalar(
            select(func.count(AnalysisDB.id)).where(AnalysisDB.created_at >= week_ago)
        ) or 0

        analyses_total = await session.scalar(select(func.count(AnalysisDB.id))) or 0

        ioc_rows = (
            await session.execute(
                select(AnalysisDB.ioc_type, func.count(AnalysisDB.id)).group_by(
                    AnalysisDB.ioc_type
                )
            )
        ).all()
        by_ioc_type = {(row[0] or "unknown"): row[1] for row in ioc_rows}

        verdict_rows = (
            await session.execute(
                select(AnalysisDB.ai_verdict, func.count(AnalysisDB.id)).group_by(
                    AnalysisDB.ai_verdict
                )
            )
        ).all()
        by_verdict = {(row[0] or "unknown"): row[1] for row in verdict_rows}

        feedback_rows = (
            await session.execute(
                select(AnalysisDB.analyst_feedback, func.count(AnalysisDB.id))
                .where(AnalysisDB.analyst_feedback != "")
                .group_by(AnalysisDB.analyst_feedback)
            )
        ).all()
        by_feedback = {row[0]: row[1] for row in feedback_rows}

        top_users_rows = (
            await session.execute(
                select(
                    UserDB.username,
                    UserDB.telegram_user_id,
                    func.count(AnalysisDB.id).label("cnt"),
                )
                .join(AnalysisDB, AnalysisDB.user_id == UserDB.id)
                .group_by(UserDB.id, UserDB.username, UserDB.telegram_user_id)
                .order_by(func.count(AnalysisDB.id).desc())
                .limit(10)
            )
        ).all()
        top_users = [
            {"username": row[0] or str(row[1]), "count": row[2]}
            for row in top_users_rows
        ]

        first_analysis_dt = await session.scalar(select(func.min(AnalysisDB.created_at)))
        distinct_users_count = (
            await session.scalar(select(func.count(func.distinct(AnalysisDB.user_id)))) or 0
        )

        avg_per_user_per_day = 0.0
        if first_analysis_dt and distinct_users_count > 0:
            days = max((now - first_analysis_dt).total_seconds() / 86400, 1)
            avg_per_user_per_day = round(analyses_total / (distinct_users_count * days), 2)

    return {
        "total_users": total_users,
        "active_users_7d": active_users,
        "analyses_today": analyses_today,
        "analyses_week": analyses_week,
        "analyses_total": analyses_total,
        "by_ioc_type": by_ioc_type,
        "by_verdict": by_verdict,
        "by_feedback": by_feedback,
        "top_users": top_users,
        "avg_per_user_per_day": avg_per_user_per_day,
    }
