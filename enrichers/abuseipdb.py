"""AbuseIPDB API v2 async client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient:
    def __init__(self, api_key: str, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Key": self._api_key,
            "Accept": "application/json",
        }

    async def check_ip(self, ip: str) -> dict[str, Any]:
        if not self._api_key:
            return {"error": True, "detail": "AbuseIPDB API key not configured"}

        url = f"{ABUSE_BASE}/check?ipAddress={quote(ip, safe=':.')}&maxAgeInDays=90"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                r = await client.get(url, headers=self._headers())
            except httpx.HTTPError as e:
                return {"error": True, "detail": str(e)}

        if r.status_code >= 400:
            return {
                "error": True,
                "status_code": r.status_code,
                "detail": r.text[:2000],
            }

        try:
            payload = r.json()
        except Exception as e:  # noqa: BLE001
            return {"error": True, "detail": f"invalid json: {e}"}

        data = (payload or {}).get("data") or {}
        if not isinstance(data, dict):
            return {"error": True, "detail": "unexpected AbuseIPDB response shape"}

        return {
            "error": False,
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "countryCode": data.get("countryCode"),
            "isp": data.get("isp"),
            "usageType": data.get("usageType"),
            "domain": data.get("domain"),
        }
