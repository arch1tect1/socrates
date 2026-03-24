"""Format LLM output for Telegram."""

from __future__ import annotations

import html


def format_telegram_report(
    llm_text: str,
    title: str = "SOCrates",
    *,
    llm_source: str | None = None,
) -> str:
    """Wrap analyst output in a compact header; escape for HTML parse mode."""
    safe = html.escape(llm_text.strip())
    header = html.escape(title)
    out = f"<b>{header}</b>\n\n{safe}"
    if llm_source and llm_source.strip():
        out += f"\n\n<i>{html.escape(llm_source.strip())}</i>"
    return out


def plain_report(llm_text: str, title: str = "SOCrates") -> str:
    """Plain text variant (no HTML)."""
    return f"{title}\n\n{llm_text.strip()}"
