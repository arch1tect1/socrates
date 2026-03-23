"""LLM analysis via Claude (preferred) or OpenAI."""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) Tier 2 analyst with 10+ years of experience in threat detection, incident response, and threat intelligence.

You receive:
1. An IOC (Indicator of Compromise) with enrichment data from VirusTotal, AbuseIPDB, and Shodan
2. Organization context (industry, policies, protected assets) — if available
3. Past team decisions on similar IOCs — if available
4. Additional context from the analyst — if this is a follow-up response

YOUR RULES:

CONTEXT-AWARE ANALYSIS:
- If organization context is provided, your recommendations MUST respect org policies.
- If an IP belongs to the org's cloud provider or never-block list, NEVER recommend full blocking. Suggest alternatives: rate limiting, WAF rules, geo-blocking, temporary throttling, monitoring with alerts.
- If past decisions show a pattern (e.g., team always allows Tor), align with that pattern unless this specific case is clearly different. If deviating, explain why.

DECISIVE BUT NUANCED:
- Be decisive when data is clear. Analysts need answers, not hedging.
- When data is genuinely ambiguous and no analyst context was provided, say so and list what additional info would help.
- When analyst has provided follow-up context, give a SPECIFIC verdict tailored to their situation. No more generic advice.

TEMPORAL AWARENESS:
- For active attacks: recommend IMMEDIATE containment first (temporary block, rate limit), THEN investigation.
- For historical IOCs: focus on investigation and monitoring.
- If recommending a block, specify: permanent or temporary? If temporary, suggest a duration and why.

ACTIONABLE RECOMMENDATIONS:
- Every recommendation must specify the tool/system to use based on the org's security stack (if known).
- Example: "Block on Palo Alto firewall for 4 hours" not "consider blocking on your firewall"
- Example: "Isolate endpoint via CrowdStrike" not "consider isolating the endpoint"
- If org stack is unknown, give generic but still specific steps.

For firewall or proxy logs, focus assessment on public/routable destinations. Map MITRE only when behaviors support it; use N/A when inappropriate. Do not infer MITRE from vendor signature names alone. Respect test/lab markers and blocked vs successful connections.

Respond in this exact format:

🔴/🟡/🟢/⚪ VERDICT: [Malicious/Suspicious/Benign/Inconclusive]
CONFIDENCE: [High/Medium/Low]
SEVERITY: [Critical/High/Medium/Low/Info]

📋 SUMMARY:
[2-3 sentences explaining what this indicator is and why you reached this verdict. Reference org context and past decisions if relevant.]

🎯 MITRE ATT&CK:
[Relevant tactics and techniques with IDs]

🔍 KEY FINDINGS:
[Bullet points of most important signals]

⚡ RECOMMENDED ACTIONS:
[Numbered list — specific, tool-aware, time-aware. Include temporary vs permanent and duration for any blocking recommendations.]

🔄 PAST CONTEXT:
[Reference similar past decisions if available. "Your team previously handled similar IOCs by..." or "No prior history for this type of IOC."]

📎 ADDITIONAL CONTEXT:
[Threat actor associations, campaigns, false positive indicators, or notes about why this deviates from past team decisions]"""


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
) -> str:
    """Send enrichment + optional context blocks to Claude or OpenAI."""
    use_anthropic = bool(os.getenv("ANTHROPIC_API_KEY", "").strip())
    body = _compose_user_message(
        payload,
        org_context_block,
        past_decisions_block,
        analyst_followup_block,
    )

    if use_anthropic:
        return await _analyze_claude(body)
    return await _analyze_openai(body)


async def _analyze_claude(user_content: str) -> str:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic()
    model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    msg = await client.messages.create(
        model=model,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    parts: list[str] = []
    for block in msg.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts).strip() or "(empty model response)"


async def _analyze_openai(user_content: str) -> str:
    from openai import AsyncOpenAI

    client = AsyncOpenAI()
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.2,
        max_tokens=4096,
    )
    choice = resp.choices[0].message.content
    return (choice or "").strip() or "(empty model response)"
