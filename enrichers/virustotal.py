"""VirusTotal API v3 async client with 4 req/min rate limiting (free tier)."""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import quote

import httpx

VT_BASE = "https://www.virustotal.com/api/v3"


class VTRateLimiter:
    """Sliding window: at most 4 requests per rolling 60s window."""

    def __init__(self, max_requests: int = 4, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._lock = asyncio.Lock()
        self._times: list[float] = []

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._times = [t for t in self._times if now - t < self._window]
            if len(self._times) >= self._max:
                wait = self._window - (now - self._times[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                now = time.monotonic()
                self._times = [t for t in self._times if now - t < self._window]
            self._times.append(time.monotonic())


def _parse_vt_body(data: dict[str, Any]) -> dict[str, Any]:
    """Extract analyst-relevant fields from VT entity JSON."""
    inner = data.get("data")
    attrs: dict[str, Any] = {}
    if isinstance(inner, dict):
        raw_attrs = inner.get("attributes")
        if isinstance(raw_attrs, dict):
            attrs = raw_attrs

    stats = attrs.get("last_analysis_stats") or {}
    rep = attrs.get("reputation")
    tags = attrs.get("tags") or []
    names = attrs.get("names") or []
    meaningful_name = attrs.get("meaningful_name")
    crowdsourced = attrs.get("crowdsourced_ids_results", [])

    associations: list[str] = []
    if isinstance(names, list):
        associations.extend(str(n) for n in names[:15])
    if meaningful_name:
        associations.append(str(meaningful_name))

    as_owner = attrs.get("as_owner") or attrs.get("network") or ""

    return {
        "reputation": rep,
        "last_analysis_stats": stats if isinstance(stats, dict) else {},
        "tags": tags if isinstance(tags, list) else [],
        "known_names_or_associations": associations[:20],
        "crowdsourced_ids": crowdsourced if isinstance(crowdsourced, list) else [],
        "as_owner": str(as_owner) if as_owner else "",
    }


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        timeout: float = 30.0,
        rate_limiter: VTRateLimiter | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._limiter = rate_limiter or VTRateLimiter()

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    async def _get(self, path: str) -> dict[str, Any]:
        await self._limiter.acquire()
        url = f"{VT_BASE}{path}"
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
            parsed = _parse_vt_body(data)
            parsed["error"] = False
            return parsed

    async def get_ip(self, ip: str) -> dict[str, Any]:
        return await self._get(f"/ip_addresses/{quote(ip, safe=':.')}")

    async def get_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"/domains/{quote(domain, safe='.')}")

    async def get_file(self, file_hash: str) -> dict[str, Any]:
        h = file_hash.lower()
        return await self._get(f"/files/{quote(h, safe='')}")
