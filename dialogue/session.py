"""Per-chat dialogue session state (in-memory; upgrade to Redis later)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


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
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: int = 600


sessions: dict[int, SessionState] = {}


def get_session(chat_id: int) -> SessionState | None:
    s = sessions.get(chat_id)
    if not s:
        return None
    age = (datetime.now(timezone.utc) - s.created_at).total_seconds()
    if age > s.ttl_seconds:
        del sessions[chat_id]
        return None
    return s


def put_session(state: SessionState) -> None:
    sessions[state.chat_id] = state


def clear_session(chat_id: int) -> None:
    sessions.pop(chat_id, None)


def purge_expired() -> None:
    now = datetime.now(timezone.utc)
    dead = [
        cid
        for cid, s in sessions.items()
        if (now - s.created_at).total_seconds() > s.ttl_seconds
    ]
    for cid in dead:
        del sessions[cid]
