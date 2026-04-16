from __future__ import annotations

import asyncio
import os
import socket
import time

import httpx

BASE = "https://api.abuseipdb.com/api/v2"


async def _resolve_domain(domain: str) -> str | None:
    """Resolve hostname to IPv4 (same approach as AbuseIPDB web UI)."""
    loop = asyncio.get_event_loop()
    try:
        results = await loop.run_in_executor(
            None, socket.getaddrinfo, domain, None, socket.AF_INET
        )
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


async def query(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}

    if ioc_type not in ("ip", "domain"):
        return {"skipped": True, "reason": "AbuseIPDB only supports IP and domain lookups"}

    start = time.time()
    target_ip = ioc
    if ioc_type == "domain":
        resolved = await _resolve_domain(ioc)
        if not resolved:
            return {"error": "Could not resolve domain to an IPv4 address for AbuseIPDB"}
        target_ip = resolved

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": target_ip, "maxAgeInDays": "90", "verbose": ""}

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

    out: dict = {
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
    if ioc_type == "domain":
        out["resolved_from"] = ioc
        out["abuse_lookup_ip"] = target_ip
        out["source_note"] = (
            f"AbuseIPDB API checks IPs only; resolved {ioc} → {target_ip} for this lookup."
        )
    return out
