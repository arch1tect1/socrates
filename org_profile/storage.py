"""JSON file storage for organization profiles."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import OrgProfile


def profile_path(data_dir: Path, chat_id: int) -> Path:
    return data_dir / "profiles" / f"{chat_id}.json"


def load_profile(data_dir: Path, chat_id: int) -> OrgProfile | None:
    path = profile_path(data_dir, chat_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return OrgProfile.from_dict(data)
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        return None


def save_profile(data_dir: Path, profile: OrgProfile) -> None:
    path = profile_path(data_dir, profile.chat_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    profile.touch()
    path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")


def parse_cidr_list(text: str) -> list[str]:
    """Parse comma-separated CIDRs; 'skip' or empty → []."""
    t = text.strip().lower()
    if not t or t == "skip":
        return []
    parts = re.split(r"[,\n;]+", text)
    out: list[str] = []
    for p in parts:
        s = p.strip()
        if s:
            out.append(s)
    return out


def parse_cloud_list(text: str) -> list[str]:
    t = text.strip().lower()
    if not t or t == "skip":
        return []
    if t == "none":
        return []
    parts = re.split(r"[,\n;]+", text)
    return [p.strip() for p in parts if p.strip()]
