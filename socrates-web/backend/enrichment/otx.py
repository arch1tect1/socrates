from __future__ import annotations

import os
import time

import httpx

BASE = "https://otx.alienvault.com/api/v1"


async def query(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("OTX_API_KEY", "")
    if not api_key:
        return {"error": "OTX_API_KEY not configured"}

    type_map = {
        "ip": f"/indicators/IPv4/{ioc}/general",
        "domain": f"/indicators/domain/{ioc}/general",
        "hash": f"/indicators/file/{ioc}/general",
        "url": f"/indicators/url/{ioc}/general",
    }

    endpoint = type_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Unsupported IOC type for OTX: {ioc_type}"}

    start = time.time()
    headers = {"X-OTX-API-KEY": api_key}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{BASE}{endpoint}", headers=headers)
        if resp.status_code in (401, 403):
            return {"error": f"OTX AlienVault authentication failed (HTTP {resp.status_code})"}
        if resp.status_code == 404:
            return {"error": "Not found in OTX database"}
        resp.raise_for_status()
        data = resp.json()

    pulses = data.get("pulse_info", {})
    pulse_count = pulses.get("count", 0)

    tags = set()
    malware_families = set()
    for pulse in pulses.get("pulses", [])[:20]:
        for tag in pulse.get("tags", []):
            tags.add(tag)
        if pulse.get("malware_families"):
            for mf in pulse["malware_families"]:
                malware_families.add(mf.get("display_name", mf.get("id", "")))

    geo = {}
    if ioc_type == "ip":
        geo = {
            "country": data.get("country_name", "N/A"),
            "city": data.get("city", "N/A"),
            "asn": data.get("asn", "N/A"),
        }

    return {
        "pulse_count": pulse_count,
        "tags": sorted(tags)[:20],
        "malware_families": sorted(malware_families)[:10],
        "geo": geo,
        "reputation": data.get("reputation", 0),
        "elapsed": round(time.time() - start, 2),
    }
