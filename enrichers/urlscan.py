"""urlscan.io API async client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

URLSCAN_BASE = "https://urlscan.io/api/v1"


class UrlscanClient:
    def __init__(self, api_key: str, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "API-Key": self._api_key,
            "Accept": "application/json",
        }

    async def search_domain(self, domain: str) -> dict[str, Any]:
        if not self._api_key:
            return {"error": True, "detail": "urlscan API key not configured"}
        q = quote(f"domain:{domain}", safe=":.")
        url = f"{URLSCAN_BASE}/search/?q={q}"
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
        if not isinstance(payload, dict):
            return {"error": True, "detail": "unexpected urlscan response"}

        results = payload.get("results") or []
        if not isinstance(results, list) or not results:
            return {"error": False, "no_data": True, "detail": "No urlscan results for domain"}

        first = results[0] if isinstance(results[0], dict) else {}
        page = first.get("page") if isinstance(first.get("page"), dict) else {}
        task = first.get("task") if isinstance(first.get("task"), dict) else {}
        stats = first.get("stats") if isinstance(first.get("stats"), dict) else {}

        related: list[str] = []
        domains = page.get("domain")
        if isinstance(domains, str) and domains:
            related.append(domains)
        if isinstance(page.get("ip"), str) and page.get("ip"):
            related.append(str(page.get("ip")))
        if isinstance(page.get("asnname"), str) and page.get("asnname"):
            related.append(str(page.get("asnname")))

        return {
            "error": False,
            "screenshot_url": page.get("screenshot"),
            "final_url": page.get("url") or task.get("url"),
            "server_info": page.get("server"),
            "related_domains": related[:20],
            "page_title": page.get("title"),
            "scan_count": payload.get("total"),
            "countries": stats.get("countries"),
        }
