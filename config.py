"""Load configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent
# CWD first, then soc-copilot/.env, then parent folder (e.g. repo root)
load_dotenv()
load_dotenv(_ROOT / ".env")
load_dotenv(_ROOT.parent / ".env")


@dataclass(frozen=True)
class Config:
    telegram_bot_token: str
    virustotal_api_key: str
    abuseipdb_api_key: str
    shodan_api_key: str
    anthropic_api_key: str | None
    openai_api_key: str | None
    http_timeout_seconds: float = 30.0


def load_config() -> Config:
    telegram = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    vt = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    abuse = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    shodan = os.getenv("SHODAN_API_KEY", "").strip()
    anthropic = os.getenv("ANTHROPIC_API_KEY", "").strip() or None
    openai = os.getenv("OPENAI_API_KEY", "").strip() or None

    missing = []
    if not telegram:
        missing.append("TELEGRAM_BOT_TOKEN")
    if not vt:
        missing.append("VIRUSTOTAL_API_KEY")
    if not anthropic and not openai:
        missing.append("ANTHROPIC_API_KEY or OPENAI_API_KEY")
    if missing:
        raise ValueError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    return Config(
        telegram_bot_token=telegram,
        virustotal_api_key=vt,
        abuseipdb_api_key=abuse,
        shodan_api_key=shodan,
        anthropic_api_key=anthropic,
        openai_api_key=openai,
    )
