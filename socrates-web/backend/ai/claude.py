from __future__ import annotations

import json
import os

import httpx

SYSTEM_PROMPT = """You are SOCrates, an AI-powered SOC analyst assistant. You receive enrichment data from multiple threat intelligence sources about an IOC (Indicator of Compromise).

Your job is NOT to summarize each source separately. Your job is to CROSS-REFERENCE all data and provide a unified triage verdict.

Think like a senior SOC analyst: look for corroborating signals across sources, identify contradictions, consider context (hosting provider, geo, timing of reports), and surface what actually matters.

## Output Format (respond in JSON):
{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "LIKELY BENIGN" | "INCONCLUSIVE",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reasoning": "2-4 paragraphs explaining your analysis. Cross-reference sources. Explain WHY, not just WHAT.",
  "mitre_attack": [
    {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "relevance": "brief explanation"}
  ],
  "recommended_actions": [
    "Action 1",
    "Action 2"
  ],
  "key_findings": [
    {"finding": "brief finding", "severity": "critical|high|medium|low|info", "source": "source name"}
  ]
}

## Guidelines:
- If VT shows detections but Shodan shows it's a major cloud provider (AWS, Azure, GCP) — consider shared infrastructure, don't auto-flag
- If AbuseIPDB reports are old (>6 months) and VT is clean — weight toward benign
- If multiple sources corroborate malicious activity — confidence should be HIGH
- Always mention what makes you uncertain if confidence is not HIGH
- Be concise but thorough in reasoning
- Return ONLY valid JSON, no markdown fencing or extra text"""


async def analyze(ioc: str, ioc_type: str, enrichment_data: dict) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not configured")

    user_message = (
        f"Analyze the following IOC: {ioc} (type: {ioc_type})\n\n"
        f"Enrichment data from threat intelligence sources:\n"
        f"{json.dumps(enrichment_data, indent=2, default=str)}"
    )

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "content-type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 4096,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_message}],
            },
        )
        resp.raise_for_status()
        data = resp.json()

    text = data["content"][0]["text"]
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    return json.loads(text)
