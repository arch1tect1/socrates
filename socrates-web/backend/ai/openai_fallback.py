from __future__ import annotations

import json
import os

import httpx

from .claude import SYSTEM_PROMPT


async def analyze(ioc: str, ioc_type: str, enrichment_data: dict) -> dict:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not configured")

    user_message = (
        f"Analyze the following IOC: {ioc} (type: {ioc_type})\n\n"
        f"Enrichment data from threat intelligence sources:\n"
        f"{json.dumps(enrichment_data, indent=2, default=str)}"
    )

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                "max_tokens": 4096,
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        data = resp.json()

    text = data["choices"][0]["message"]["content"].strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    return json.loads(text)
