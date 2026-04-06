"""Per-chat dialogue session state (in-memory cache + PostgreSQL persistence)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

BAKU_TZ = timezone(timedelta(hours=4))
from typing import Any

from sqlalchemy import delete, select


@dataclass
class SessionState:
    chat_id: int
    original_input: str
    ioc_type: str
    ioc_value: str
    enrichment_data: dict[str, Any]
    payload: dict[str, Any]
    org_profile_dict: dict[str, Any] | None
    ambiguity_flags: list[str]
    followup_questions: list[str]
    analyst_responses: list[str] = field(default_factory=list)
    status: str = "awaiting_followup"
    created_at: datetime = field(default_factory=lambda: datetime.now(BAKU_TZ))
    ttl_seconds: int = 3600


# In-memory cache for fast access
sessions: dict[int, SessionState] = {}


def _parse_dt(raw: str) -> datetime:
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=BAKU_TZ)
    return dt


def _state_to_jsonable(state: SessionState) -> dict[str, Any]:
    d = asdict(state)
    d["created_at"] = state.created_at.isoformat()
    return d


def _state_from_dict(d: dict[str, Any]) -> SessionState:
    ca = d.get("created_at", "")
    created_at = _parse_dt(ca) if isinstance(ca, str) and ca else datetime.now(BAKU_TZ)
    return SessionState(
        chat_id=int(d["chat_id"]),
        original_input=str(d.get("original_input", "")),
        ioc_type=str(d.get("ioc_type", "")),
        ioc_value=str(d.get("ioc_value", "")),
        enrichment_data=dict(d.get("enrichment_data") or {}),
        payload=dict(d.get("payload") or {}),
        org_profile_dict=d.get("org_profile_dict"),
        ambiguity_flags=list(d.get("ambiguity_flags") or []),
        followup_questions=list(d.get("followup_questions") or []),
        analyst_responses=list(d.get("analyst_responses") or []),
        status=str(d.get("status", "awaiting_followup")),
        created_at=created_at,
        ttl_seconds=int(d.get("ttl_seconds", 3600)),
    )


def _is_expired(state: SessionState) -> bool:
    age = (datetime.now(BAKU_TZ) - state.created_at).total_seconds()
    return age > state.ttl_seconds


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

async def _write_session_db(state: SessionState) -> None:
    from database.crud import get_or_create_user
    from database.engine import get_async_session
    from database.models import SessionDB, UserDB

    user_id = await get_or_create_user(state.chat_id)
    expires_at = state.created_at + timedelta(seconds=state.ttl_seconds)
    state_dict = _state_to_jsonable(state)

    async with get_async_session() as session:
        result = await session.execute(
            select(SessionDB).where(
                SessionDB.user_id == user_id,
                SessionDB.session_type == "dialogue",
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.state = state_dict
            existing.expires_at = expires_at
        else:
            session.add(
                SessionDB(
                    user_id=user_id,
                    session_type="dialogue",
                    state=state_dict,
                    expires_at=expires_at,
                )
            )
        await session.commit()


async def _read_session_db(chat_id: int) -> SessionState | None:
    from database.engine import get_async_session
    from database.models import SessionDB, UserDB

    async with get_async_session() as session:
        result = await session.execute(
            select(SessionDB)
            .join(UserDB)
            .where(
                UserDB.telegram_user_id == chat_id,
                SessionDB.session_type == "dialogue",
            )
        )
        row = result.scalar_one_or_none()
        if not row or not row.state:
            return None
        try:
            return _state_from_dict(row.state)
        except (KeyError, TypeError, ValueError):
            return None


async def _delete_session_db(chat_id: int) -> None:
    from database.engine import get_async_session
    from database.models import SessionDB, UserDB

    async with get_async_session() as session:
        user_result = await session.execute(
            select(UserDB.id).where(UserDB.telegram_user_id == chat_id)
        )
        user_id = user_result.scalar_one_or_none()
        if user_id:
            await session.execute(
                delete(SessionDB).where(
                    SessionDB.user_id == user_id,
                    SessionDB.session_type == "dialogue",
                )
            )
            await session.commit()


# ---------------------------------------------------------------------------
# Public API (async, memory + DB write-through)
# ---------------------------------------------------------------------------

async def get_session(chat_id: int) -> SessionState | None:
    s = sessions.get(chat_id)
    if s:
        if _is_expired(s):
            sessions.pop(chat_id, None)
            await _delete_session_db(chat_id)
            return None
        return s

    loaded = await _read_session_db(chat_id)
    if loaded:
        if _is_expired(loaded):
            await _delete_session_db(chat_id)
            return None
        sessions[chat_id] = loaded
        return loaded
    return None


async def put_session(state: SessionState) -> None:
    sessions[state.chat_id] = state
    await _write_session_db(state)


async def clear_session(chat_id: int) -> None:
    sessions.pop(chat_id, None)
    await _delete_session_db(chat_id)


def purge_expired() -> None:
    now = datetime.now(BAKU_TZ)
    dead = [
        cid
        for cid, s in sessions.items()
        if (now - s.created_at).total_seconds() > s.ttl_seconds
    ]
    for cid in dead:
        del sessions[cid]
