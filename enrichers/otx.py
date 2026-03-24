"""AlienVault OTX API async client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXClient:
    def __init__(self, api_key: str, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "X-OTX-API-KEY": self._api_key,
            "Accept": "application/json",
        }

    async def _get(self, path: str) -> dict[str, Any]:
        if not self._api_key:
            return {"error": True, "detail": "OTX API key not configured"}
        url = f"{OTX_BASE}{path}"
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
            data = r.json()
        except Exception as e:  # noqa: BLE001
            return {"error": True, "detail": f"invalid json: {e}"}
        if not isinstance(data, dict):
            return {"error": True, "detail": "unexpected OTX response"}
        return self._parse_general(data)

    def _parse_general(self, data: dict[str, Any]) -> dict[str, Any]:
        pulse_info = data.get("pulse_info") if isinstance(data.get("pulse_info"), dict) else {}
        pulses = pulse_info.get("pulses") if isinstance(pulse_info.get("pulses"), list) else []

        parsed_pulses: list[dict[str, Any]] = []
        all_tags: set[str] = set()
        threat_actors: set[str] = set()
        malware_families: set[str] = set()

        for p in pulses[:30]:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").strip()
            tags = p.get("tags") if isinstance(p.get("tags"), list) else []
            ad = p.get("adversary")
            mal = p.get("malware_families")
            parsed_tags = [str(t) for t in tags if str(t).strip()]
            for t in parsed_tags:
                all_tags.add(t)
            if isinstance(ad, str) and ad.strip():
                threat_actors.add(ad.strip())
            if isinstance(mal, list):
                for m in mal:
                    s = str(m).strip()
                    if s:
                        malware_families.add(s)
            parsed_pulses.append({"name": name, "tags": parsed_tags[:15]})

        pulse_count = pulse_info.get("count")
        if not isinstance(pulse_count, int):
            pulse_count = len(parsed_pulses)

        return {
            "error": False,
            "pulse_count": pulse_count,
            "related_pulses": parsed_pulses[:15],
            "known_threat_actors": sorted(threat_actors)[:20],
            "malware_families": sorted(malware_families)[:20],
            "pulse_tags": sorted(all_tags)[:50],
        }

    async def get_ip(self, ip: str) -> dict[str, Any]:
        return await self._get(f"/IPv4/{quote(ip, safe=':.')}/general")

    async def get_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"/domain/{quote(domain, safe='.')}/general")

    async def get_file(self, file_hash: str) -> dict[str, Any]:
        return await self._get(f"/file/{quote(file_hash.lower(), safe='')}/general")
