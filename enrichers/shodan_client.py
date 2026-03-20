"""Shodan REST API async client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

SHODAN_BASE = "https://api.shodan.io"


class ShodanClient:
    def __init__(self, api_key: str, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    async def host(self, ip: str) -> dict[str, Any]:
        if not self._api_key:
            return {"error": True, "detail": "Shodan API key not configured"}

        path = f"/shodan/host/{quote(ip, safe=':.')}"
        url = f"{SHODAN_BASE}{path}?key={quote(self._api_key, safe='')}"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                r = await client.get(url)
            except httpx.HTTPError as e:
                return {"error": True, "detail": str(e)}

        if r.status_code == 404:
            return {"error": False, "no_data": True, "detail": "No Shodan data for host"}

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
            return {"error": True, "detail": "unexpected Shodan response"}

        vulns = data.get("vulns")
        if isinstance(vulns, list):
            vuln_list = vulns
        elif isinstance(vulns, dict):
            vuln_list = list(vulns.keys())
        else:
            vuln_list = []

        hostnames = data.get("hostnames") or []
        if not isinstance(hostnames, list):
            hostnames = []

        ports = data.get("ports") or []
        if not isinstance(ports, list):
            ports = []

        return {
            "error": False,
            "open_ports": ports,
            "vulns": vuln_list[:50],
            "os": data.get("os"),
            "hostnames": hostnames[:20],
            "org": data.get("org"),
            "tags": data.get("tags") or [],
        }
