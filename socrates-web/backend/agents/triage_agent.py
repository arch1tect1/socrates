"""L1 triage agent — Anthropic tool-calling loop + verdict persistence."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
from uuid import UUID

import httpx

from ..cache import get_supabase_client
from ..services import alert_ingestion
from .tool_executor import ToolExecutor
from .tools import TRIAGE_TOOLS

logger = logging.getLogger("socrates.triage_agent")

SYSTEM_PROMPT = """You are a senior SOC L1 analyst investigating security alerts.

For each alert, you have access to tools that query threat intelligence sources.
Your goal: determine if the alert represents a true positive (malicious/suspicious activity)
or false positive (benign), and recommend an action.

Investigation approach:
1. Start by examining the alert context (rule, source, IOCs present)
2. Query the most relevant intel sources first — don't just run every tool
3. If initial sources are inconclusive, dig deeper (WHOIS, similar alerts)
4. Stop when you have enough evidence to make a confident judgment
5. Typical investigation uses 3-6 tool calls — more than 10 means you're fishing

When you have enough information, respond with a final JSON verdict (no more tool calls).
Your final reply must be ONLY a JSON object with this exact shape (no markdown fences):
{
  "verdict": "malicious" | "suspicious" | "benign" | "inconclusive",
  "confidence": 0.0,
  "reasoning": "step-by-step explanation of your conclusion",
  "recommended_action": "block_ioc | isolate_host | escalate_l2 | close_fp | monitor"
}

confidence must be a number between 0 and 1.

Be decisive. If evidence is weak in both directions, use verdict 'inconclusive' — don't pretend to be confident."""

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
MAX_ITERATIONS = 15
TOOL_RESULT_MAX_CHARS = 8000

_executor = ToolExecutor()


def _triage_model() -> str:
    return os.getenv("ANTHROPIC_TRIAGE_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def _serialize_content_block(block: dict[str, Any]) -> dict[str, Any]:
    btype = block.get("type")
    if btype == "text":
        t = block.get("text") or ""
        return {"type": "text", "text": t[:8000]}
    if btype == "tool_use":
        return {
            "type": "tool_use",
            "id": block.get("id"),
            "name": block.get("name"),
            "input": block.get("input"),
        }
    return {"type": str(btype), "snippet": json.dumps(block, default=str)[:4000]}


def _parse_verdict_json(text: str) -> dict[str, Any] | None:
    t = (text or "").strip()
    if not t:
        return None
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.IGNORECASE)
        t = re.sub(r"\s*```$", "", t)
        t = t.strip()
    try:
        obj = json.loads(t)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}\s*$", t)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
        else:
            return None

    if not isinstance(obj, dict):
        return None
    v = str(obj.get("verdict", "")).lower().strip()
    if v not in ("malicious", "suspicious", "benign", "inconclusive"):
        return None
    try:
        conf = float(obj.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))
    reasoning = str(obj.get("reasoning", "")).strip() or "No reasoning provided."
    action = str(obj.get("recommended_action", "monitor")).strip() or "monitor"
    return {
        "verdict": v,
        "confidence": conf,
        "reasoning": reasoning,
        "recommended_action": action,
    }


def _summarize_tool_result(result: dict[str, Any]) -> str:
    if result.get("cached"):
        return "cache_hit"
    if result.get("error"):
        return "error"
    if result.get("skipped"):
        return "skipped"
    return "ok"


async def _anthropic_messages(
    *,
    client: httpx.AsyncClient,
    messages: list[dict[str, Any]],
    api_key: str,
) -> dict[str, Any]:
    model = _triage_model()
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": 4096,
        "system": SYSTEM_PROMPT,
        "tools": TRIAGE_TOOLS,
        "messages": messages,
    }
    resp = await client.post(
        ANTHROPIC_URL,
        headers={
            "x-api-key": api_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        },
        json=body,
        timeout=180.0,
    )
    resp.raise_for_status()
    return resp.json()


async def _save_verdict(
    alert_id: UUID,
    verdict_data: dict[str, Any],
    tools_used: list[dict[str, Any]],
    agent_trace: list[dict[str, Any]],
) -> None:
    sb = get_supabase_client()
    if sb is None:
        logger.error("triage: Supabase unavailable, cannot save verdict alert_id=%s", alert_id)
        return

    row = {
        "alert_id": str(alert_id),
        "verdict": verdict_data["verdict"],
        "confidence": verdict_data["confidence"],
        "reasoning": verdict_data["reasoning"],
        "tools_used": tools_used,
        "recommended_action": verdict_data.get("recommended_action"),
        "agent_trace": agent_trace,
    }
    try:
        sb.table("verdicts").insert(row).execute()
        logger.info("triage: verdict saved alert_id=%s verdict=%s", alert_id, verdict_data["verdict"])
    except Exception as e:
        logger.exception("triage: verdict insert failed: %s", e)


async def investigate(alert_id: UUID | str) -> None:
    """
    Run after alert ingest (use FastAPI BackgroundTasks so the ASGI stack awaits completion).
    A plain sync fire-and-forget task can exit before work finishes on serverless.
    """
    await _investigate_async(UUID(str(alert_id)))


async def _investigate_async(alert_id: UUID) -> None:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        logger.error("triage: ANTHROPIC_API_KEY not set alert_id=%s", alert_id)
        await _save_verdict(
            alert_id,
            {
                "verdict": "inconclusive",
                "confidence": 0.2,
                "reasoning": "ANTHROPIC_API_KEY is not configured on the server.",
                "recommended_action": "escalate_l2",
            },
            [],
            [{"error": "missing_api_key"}],
        )
        return

    sb = get_supabase_client()
    if sb is None:
        logger.error("triage: Supabase not configured alert_id=%s", alert_id)
        return

    try:
        alert = alert_ingestion.fetch_alert(alert_id)
    except Exception as e:
        logger.warning("triage: could not load alert %s: %s", alert_id, e)
        return

    alert_blob = alert.model_dump(mode="json")
    user_text = f"Alert to investigate:\n{json.dumps(alert_blob, default=str, indent=2)}"

    try:
        sb.table("alerts").update({"status": "investigating"}).eq("id", str(alert_id)).execute()
    except Exception as e:
        logger.warning("triage: could not set status investigating: %s", e)

    messages: list[dict[str, Any]] = [{"role": "user", "content": user_text}]
    trace: list[dict[str, Any]] = []
    tools_used: list[dict[str, Any]] = []

    async with httpx.AsyncClient() as client:
        for iteration in range(MAX_ITERATIONS):
            try:
                data = await _anthropic_messages(client=client, messages=messages, api_key=api_key)
            except httpx.HTTPStatusError as e:
                err_body = e.response.text[:2000] if e.response else ""
                logger.exception("triage: Anthropic HTTP error: %s", err_body)
                await _save_verdict(
                    alert_id,
                    {
                        "verdict": "inconclusive",
                        "confidence": 0.3,
                        "reasoning": f"Anthropic API error: {e.response.status_code if e.response else e}",
                        "recommended_action": "escalate_l2",
                    },
                    tools_used,
                    trace + [{"error": "anthropic_http", "detail": err_body}],
                )
                return
            except Exception as e:
                logger.exception("triage: Anthropic request failed")
                await _save_verdict(
                    alert_id,
                    {
                        "verdict": "inconclusive",
                        "confidence": 0.3,
                        "reasoning": f"Agent error: {e!s}",
                        "recommended_action": "escalate_l2",
                    },
                    tools_used,
                    trace + [{"error": str(e)}],
                )
                return

            stop_reason = data.get("stop_reason") or ""
            content = data.get("content") or []

            trace.append({
                "iteration": iteration,
                "stop_reason": stop_reason,
                "content": [_serialize_content_block(b) for b in content if isinstance(b, dict)],
            })

            if stop_reason == "max_tokens":
                await _save_verdict(
                    alert_id,
                    {
                        "verdict": "inconclusive",
                        "confidence": 0.35,
                        "reasoning": "Model hit max_tokens before finishing.",
                        "recommended_action": "escalate_l2",
                    },
                    tools_used,
                    trace,
                )
                return

            tool_blocks = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]

            # Prefer tool rounds when the model emitted tool_use blocks (ignore stray stop_reason values).
            if not tool_blocks:
                final_text = "".join(
                    b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
                )
                parsed = _parse_verdict_json(final_text)
                if parsed:
                    await _save_verdict(alert_id, parsed, tools_used, trace)
                    return
                await _save_verdict(
                    alert_id,
                    {
                        "verdict": "inconclusive",
                        "confidence": 0.4,
                        "reasoning": final_text[:8000] or "Model ended without valid JSON verdict.",
                        "recommended_action": "escalate_l2",
                    },
                    tools_used,
                    trace,
                )
                return

            messages.append({"role": "assistant", "content": content})

            tool_result_blocks: list[dict[str, Any]] = []
            for block in tool_blocks:
                name = block.get("name") or ""
                tool_id = block.get("id") or ""
                raw_input = block.get("input")
                tool_input = raw_input if isinstance(raw_input, dict) else {}
                result = await _executor.execute(name, tool_input)
                tools_used.append({
                    "name": name,
                    "input": tool_input,
                    "result_summary": _summarize_tool_result(result),
                })
                payload = json.dumps(result, default=str)
                if len(payload) > TOOL_RESULT_MAX_CHARS:
                    payload = payload[: TOOL_RESULT_MAX_CHARS - 80] + "\n...truncated..."
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": payload,
                })

            messages.append({"role": "user", "content": tool_result_blocks})

    await _save_verdict(
        alert_id,
        {
            "verdict": "inconclusive",
            "confidence": 0.3,
            "reasoning": "Max iterations reached without a decisive JSON verdict.",
            "recommended_action": "escalate_l2",
        },
        tools_used,
        trace,
    )
