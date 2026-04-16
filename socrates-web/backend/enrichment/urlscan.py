from __future__ import annotations

import asyncio
import os
import time

import httpx

BASE = "https://urlscan.io/api/v1"


async def _search_existing(client: httpx.AsyncClient, headers: dict, ioc: str, ioc_type: str) -> dict | None:
    """Search for existing scan results when live scanning fails."""
    query = f"domain:{ioc}" if ioc_type == "domain" else f"page.url:{ioc}"
    resp = await client.get(
        f"{BASE}/search/",
        headers=headers,
        params={"q": query, "size": 1},
    )
    if resp.status_code != 200:
        return None

    data = resp.json()
    results = data.get("results", [])
    if not results:
        return None

    hit = results[0]
    page = hit.get("page", {})
    verdicts = hit.get("verdicts", {}).get("overall", {})
    task = hit.get("task", {})

    return {
        "final_url": page.get("url", "N/A"),
        "domain": page.get("domain", "N/A"),
        "server": page.get("server", "N/A"),
        "ip": page.get("ip", "N/A"),
        "country": page.get("country", "N/A"),
        "status_code": page.get("status", "N/A"),
        "is_malicious": verdicts.get("malicious", False),
        "verdict_score": verdicts.get("score", 0),
        "verdict_categories": verdicts.get("categories", []),
        "screenshot_url": task.get("screenshotURL", ""),
        "result_url": f"https://urlscan.io/result/{task.get('uuid', '')}/",
        "source_note": "From cached/historical scan results",
    }


async def query(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("URLSCAN_API_KEY", "")
    if not api_key:
        return {"error": "URLSCAN_API_KEY not configured"}

    if ioc_type not in ("url", "domain"):
        return {"skipped": True, "reason": "URLScan only supports URL/domain lookups"}

    start = time.time()
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    scan_url = ioc if ioc_type == "url" else f"https://{ioc}"

    async with httpx.AsyncClient(timeout=60) as client:
        submit = await client.post(
            f"{BASE}/scan/",
            headers=headers,
            json={"url": scan_url, "visibility": "unlisted"},
        )

        if submit.status_code != 200:
            existing = await _search_existing(client, headers, ioc, ioc_type)
            if existing:
                existing["elapsed"] = round(time.time() - start, 2)
                return existing

            try:
                err_body = submit.json()
                msg = err_body.get("message") or err_body.get("description") or f"HTTP {submit.status_code}"
            except Exception:
                msg = f"HTTP {submit.status_code}"
            return {"error": f"URLScan.io: {msg}"}

        scan_data = submit.json()
        uuid = scan_data.get("uuid")

        if not uuid:
            return {"error": "No scan UUID returned"}

        result = None
        for attempt in range(6):
            await asyncio.sleep(5)
            try:
                res = await client.get(f"{BASE}/result/{uuid}/")
                if res.status_code == 200:
                    result = res.json()
                    break
            except httpx.HTTPError:
                continue

        if not result:
            return {
                "scan_uuid": uuid,
                "status": "pending",
                "note": "Scan submitted but results not yet available. Check manually.",
                "result_url": f"https://urlscan.io/result/{uuid}/",
                "elapsed": round(time.time() - start, 2),
            }

    page = result.get("page", {})
    lists = result.get("lists", {})
    verdicts = result.get("verdicts", {}).get("overall", {})
    stats = result.get("stats", {})

    screenshot_url = result.get("task", {}).get("screenshotURL", "")

    technologies = []
    for tech in stats.get("tlsStats", [])[:5]:
        technologies.append(tech.get("protocol", ""))

    return {
        "final_url": page.get("url", "N/A"),
        "domain": page.get("domain", "N/A"),
        "server": page.get("server", "N/A"),
        "ip": page.get("ip", "N/A"),
        "country": page.get("country", "N/A"),
        "status_code": page.get("status", "N/A"),
        "is_malicious": verdicts.get("malicious", False),
        "verdict_score": verdicts.get("score", 0),
        "verdict_categories": verdicts.get("categories", []),
        "detected_urls": lists.get("urls", [])[:10],
        "screenshot_url": screenshot_url,
        "result_url": f"https://urlscan.io/result/{uuid}/",
        "elapsed": round(time.time() - start, 2),
    }
