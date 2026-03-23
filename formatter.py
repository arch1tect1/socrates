"""Format LLM output for Telegram."""

from __future__ import annotations

import html


def format_telegram_report(llm_text: str, title: str = "SOCrates") -> str:
    """Wrap analyst output in a compact header; escape for HTML parse mode."""
    safe = html.escape(llm_text.strip())
    header = html.escape(title)
    return f"<b>{header}</b>\n\n{safe}"


def plain_report(llm_text: str, title: str = "SOCrates") -> str:
    """Plain text variant (no HTML)."""
    return f"{title}\n\n{llm_text.strip()}"
