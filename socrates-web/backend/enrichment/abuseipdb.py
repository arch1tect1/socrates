from __future__ import annotations

import os
import time

import httpx

BASE = "https://api.abuseipdb.com/api/v2"


async def query(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}

    if ioc_type != "ip":
        return {"skipped": True, "reason": "AbuseIPDB only supports IP lookups"}

    start = time.time()
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": "90", "verbose": ""}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{BASE}/check", headers=headers, params=params)
        if resp.status_code in (401, 403):
            return {"error": f"AbuseIPDB authentication failed (HTTP {resp.status_code})"}
        if resp.status_code == 429:
            return {"error": "AbuseIPDB rate limit exceeded"}
        resp.raise_for_status()
        raw = resp.json()

    data = raw.get("data", {})
    score = data.get("abuseConfidenceScore", 0)

    if score <= 30:
        severity = "low"
    elif score <= 70:
        severity = "medium"
    else:
        severity = "high"

    categories = data.get("reports", [])
    category_names = set()
    for report in categories[:50]:
        for cat in report.get("categories", []):
            category_names.add(cat)

    return {
        "abuse_confidence_score": score,
        "severity": severity,
        "total_reports": data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt", "N/A"),
        "isp": data.get("isp", "N/A"),
        "usage_type": data.get("usageType", "N/A"),
        "domain": data.get("domain", "N/A"),
        "country_code": data.get("countryCode", "N/A"),
        "is_whitelisted": data.get("isWhitelisted", False),
        "abuse_categories": sorted(category_names),
        "elapsed": round(time.time() - start, 2),
    }
