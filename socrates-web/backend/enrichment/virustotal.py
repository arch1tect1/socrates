from __future__ import annotations

import base64
import os
import time

import httpx

BASE = "https://www.virustotal.com/api/v3"


async def query(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}

    headers = {"x-apikey": api_key}
    start = time.time()

    type_to_endpoint = {
        "ip": f"/ip_addresses/{ioc}",
        "domain": f"/domains/{ioc}",
        "hash": f"/files/{ioc}",
    }

    if ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        endpoint = f"/urls/{url_id}"
    elif ioc_type in type_to_endpoint:
        endpoint = type_to_endpoint[ioc_type]
    else:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{BASE}{endpoint}", headers=headers)
        if resp.status_code in (401, 403):
            return {"error": f"VirusTotal authentication failed (HTTP {resp.status_code})"}
        if resp.status_code == 404:
            return {"error": "Not found in VirusTotal database"}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded"}
        resp.raise_for_status()
        raw = resp.json()

    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    total_engines = sum(stats.values()) if stats else 0
    reputation = attrs.get("reputation", "N/A")
    tags = attrs.get("tags", [])
    last_analysis = attrs.get("last_analysis_date", "N/A")

    popular_threat = attrs.get("popular_threat_classification", {})
    threat_label = popular_threat.get("suggested_threat_label", "N/A")
    threat_categories = [
        c.get("value", "") for c in popular_threat.get("popular_threat_category", [])
    ]

    return {
        "detection_ratio": f"{malicious}/{total_engines}",
        "malicious_count": malicious,
        "total_engines": total_engines,
        "community_score": reputation,
        "tags": tags[:15],
        "threat_label": threat_label,
        "threat_categories": threat_categories[:10],
        "last_analysis_date": last_analysis,
        "elapsed": round(time.time() - start, 2),
    }
