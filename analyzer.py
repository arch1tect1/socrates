"""LLM analysis via Claude (preferred) or OpenAI."""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) Tier 2 analyst with 10+ years of experience in threat detection, incident response, and threat intelligence.

You receive an IOC (Indicator of Compromise) along with enrichment data from VirusTotal, AbuseIPDB, and Shodan.

Your job is to analyze all available data and produce a structured security assessment.

RULES:
- Be decisive. Analysts need clear answers, not hedging.
- If data strongly suggests malicious activity, say so directly.
- For firewall or proxy logs that include src and dst, focus threat assessment on **public/routable** destinations and extracted external IOCs; treat RFC1918/private source IPs as internal context unless no public IOC exists.
- Map MITRE ATT&CK when concrete behaviors support it; use **N/A** if the alert is purely ambiguous, test-titled, or lacks enough detail for a fair mapping.
- Recommend concrete next steps, not vague advice.
- If enrichment data is missing or APIs returned errors, note it and work with what you have.
- Consider the combination of signals, not just individual scores.
- Flag false positive indicators if you see them (e.g. CDN IPs, legitimate services).
- If the log shows **action=deny/block** or similar, treat it as a **prevented** attempt unless other data proves success; do not describe it as confirmed exfiltration or active C2 session. Match response guidance to what is actually known (blocked attempt vs successful malicious connection).
- If signature/rule fields contain obvious **test/lab** markers (e.g. EICAR, test-proxy, lab-, sandbox, synthetic), call that out: severity and actions should reflect possible **drill/exercise** unless threat intel strongly confirms real malicious infrastructure independent of the label.
- For MITRE ATT&CK, list only techniques **clearly supported** by the log and enrichment (protocol, ports, behavior). Do not force-fit IDs (e.g. avoid T1095 Non-Application Layer Protocol for ordinary TCP/443 HTTPS-style traffic unless the evidence says non-application-layer).
- Do **not** pick MITRE IDs from **vendor signature strings** alone (e.g. the substring `proxy` in `EICAR-test-proxy` is not evidence of technique T1090; rule names are marketing labels, not observed tactics).

Respond ONLY in this exact format:

🔴/🟡/🟢/⚪ VERDICT: [Malicious/Suspicious/Benign/Inconclusive]
CONFIDENCE: [High/Medium/Low]
SEVERITY: [Critical/High/Medium/Low/Info]

📋 SUMMARY:
[2-3 sentences explaining what this indicator is and why you reached this verdict]

🎯 MITRE ATT&CK:
[List relevant tactics and techniques with IDs, or "N/A" if not applicable]

🔍 KEY FINDINGS:
[Bullet points of the most important enrichment signals that informed your verdict]

⚡ RECOMMENDED ACTIONS:
[Numbered list of specific steps the analyst should take]

📎 ADDITIONAL CONTEXT:
[Any known threat actor associations, campaigns, malware families, or notes about potential false positives]"""


def _payload_to_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, default=str)


async def analyze_enrichment(payload: dict[str, Any]) -> str:
    """Send enrichment JSON to Claude or OpenAI; return assistant text."""
    use_anthropic = bool(os.getenv("ANTHROPIC_API_KEY", "").strip())
    body = _payload_to_text(payload)

    if use_anthropic:
        return await _analyze_claude(body)
    return await _analyze_openai(body)


async def _analyze_claude(user_content: str) -> str:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic()
    # Default snapshot; override with CLAUDE_MODEL. Older IDs (e.g. claude-3-5-sonnet-20241022) may 404.
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
