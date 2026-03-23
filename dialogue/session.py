"""Per-chat dialogue session state (in-memory + optional disk for restarts)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
    ttl_seconds: int = 3600


sessions: dict[int, SessionState] = {}


def _session_path(data_dir: Path, chat_id: int) -> Path:
    return data_dir / "dialogue_sessions" / f"{chat_id}.json"


def _parse_dt(raw: str) -> datetime:
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _state_to_jsonable(state: SessionState) -> dict[str, Any]:
    d = asdict(state)
    d["created_at"] = state.created_at.isoformat()
    return d


def _state_from_dict(d: dict[str, Any]) -> SessionState:
    ca = d.get("created_at", "")
    created_at = _parse_dt(ca) if isinstance(ca, str) and ca else datetime.now(timezone.utc)
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


def _write_session_file(data_dir: Path, state: SessionState) -> None:
    path = _session_path(data_dir, state.chat_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_state_to_jsonable(state), indent=2, default=str),
        encoding="utf-8",
    )


def _read_session_file(data_dir: Path, chat_id: int) -> SessionState | None:
    path = _session_path(data_dir, chat_id)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        state = _state_from_dict(raw)
    except (KeyError, TypeError, ValueError):
        return None
    age = (datetime.now(timezone.utc) - state.created_at).total_seconds()
    if age > state.ttl_seconds:
        path.unlink(missing_ok=True)
        return None
    return state


def _delete_session_file(data_dir: Path, chat_id: int) -> None:
    path = _session_path(data_dir, chat_id)
    path.unlink(missing_ok=True)


def _is_expired(state: SessionState) -> bool:
    age = (datetime.now(timezone.utc) - state.created_at).total_seconds()
    return age > state.ttl_seconds


def get_session(chat_id: int, data_dir: Path | None = None) -> SessionState | None:
    s = sessions.get(chat_id)
    if s:
        if _is_expired(s):
            sessions.pop(chat_id, None)
            if data_dir is not None:
                _delete_session_file(data_dir, chat_id)
            return None
        return s

    if data_dir is not None:
        loaded = _read_session_file(data_dir, chat_id)
        if loaded:
            if _is_expired(loaded):
                _delete_session_file(data_dir, chat_id)
                return None
            sessions[chat_id] = loaded
            return loaded
    return None


def put_session(state: SessionState, data_dir: Path | None = None) -> None:
    sessions[state.chat_id] = state
    if data_dir is not None:
        _write_session_file(data_dir, state)


def clear_session(chat_id: int, data_dir: Path | None = None) -> None:
    sessions.pop(chat_id, None)
    if data_dir is not None:
        _delete_session_file(data_dir, chat_id)


def purge_expired() -> None:
    now = datetime.now(timezone.utc)
    dead = [
        cid
        for cid, s in sessions.items()
        if (now - s.created_at).total_seconds() > s.ttl_seconds
    ]
    for cid in dead:
        del sessions[cid]
