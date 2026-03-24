"""Load LLM and dialogue prompt text from files under ``prompts/``."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def load_system_prompt() -> str:
    return (_DIR / "system_soc_analyst.txt").read_text(encoding="utf-8").strip()


@lru_cache(maxsize=1)
def load_followup_questions() -> dict[str, list[str]]:
    raw = json.loads((_DIR / "followup_questions.json").read_text(encoding="utf-8"))
    return {str(k): list(v) for k, v in raw.items()}


@lru_cache(maxsize=1)
def load_org_context_footer() -> str:
    return (_DIR / "org_context_footer.txt").read_text(encoding="utf-8").strip()


@lru_cache(maxsize=1)
def load_past_decisions_footer() -> str:
    return (_DIR / "past_decisions_footer.txt").read_text(encoding="utf-8").strip()


@lru_cache(maxsize=1)
def load_vpn_guidance() -> dict[str, str]:
    raw = json.loads((_DIR / "vpn_guidance.json").read_text(encoding="utf-8"))
    return {str(k): str(v) for k, v in raw.items()}
