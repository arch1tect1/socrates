"""LLM analysis via Claude (Anthropic) or OpenAI (ChatGPT API).

Which backend runs:
- If ``ANTHROPIC_API_KEY`` is set (non-empty), **Claude** is used (``CLAUDE_MODEL``, default
  ``claude-sonnet-4-20250514``).
- Otherwise **OpenAI** is used (``OPENAI_MODEL``, default ``gpt-4o-mini``) — the same API family
  as ChatGPT, not the consumer chat UI.

System prompt text lives in ``prompts/system_soc_analyst.txt`` (loaded at runtime).
"""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

from prompts.load import load_system_prompt

load_dotenv()


def _payload_to_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, default=str)


def _compose_user_message(
    payload: dict[str, Any],
    org_context_block: str,
    past_decisions_block: str,
    analyst_followup_block: str,
) -> str:
    parts: list[str] = []
    if org_context_block.strip():
        parts.append(org_context_block.strip())
    if past_decisions_block.strip():
        parts.append(past_decisions_block.strip())
    if analyst_followup_block.strip():
        parts.append(analyst_followup_block.strip())
    parts.append("ENRICHMENT AND CASE DATA (JSON):\n" + _payload_to_text(payload))
    return "\n\n".join(parts)


async def analyze_enrichment(
    payload: dict[str, Any],
    *,
    org_context_block: str = "",
    past_decisions_block: str = "",
    analyst_followup_block: str = "",
) -> tuple[str, str]:
    """Send enrichment to the LLM.

    Returns ``(analysis_text, source_label)`` where ``source_label`` identifies the provider
    and model (for display or logging), e.g. ``"Claude (claude-sonnet-4-20250514)"``.
    """
    use_anthropic = bool(os.getenv("ANTHROPIC_API_KEY", "").strip())
    body = _compose_user_message(
        payload,
        org_context_block,
        past_decisions_block,
        analyst_followup_block,
    )

    if use_anthropic:
        model = (os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514") or "").strip()
        if not model:
            model = "claude-sonnet-4-20250514"
        text = await _analyze_claude(body, model=model)
        return text, f"Claude ({model})"

    model = (os.getenv("OPENAI_MODEL", "gpt-4o-mini") or "").strip()
    if not model:
        model = "gpt-4o-mini"
    text = await _analyze_openai(body, model=model)
    return text, f"OpenAI ChatGPT API ({model})"


async def _analyze_claude(user_content: str, *, model: str) -> str:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic()
    msg = await client.messages.create(
        model=model,
        max_tokens=4096,
        system=load_system_prompt(),
        messages=[{"role": "user", "content": user_content}],
    )
    parts: list[str] = []
    for block in msg.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts).strip() or "(empty model response)"


async def _analyze_openai(user_content: str, *, model: str) -> str:
    from openai import AsyncOpenAI

    client = AsyncOpenAI()
    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": load_system_prompt()},
            {"role": "user", "content": user_content},
        ],
        temperature=0.2,
        max_tokens=4096,
    )
    choice = resp.choices[0].message.content
    return (choice or "").strip() or "(empty model response)"
