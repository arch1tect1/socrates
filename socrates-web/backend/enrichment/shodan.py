from __future__ import annotations

import asyncio
import os
import socket
import time

import httpx

BASE = "https://api.shodan.io"


async def _resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP using system DNS (works on all Shodan plans)."""
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
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return {"error": "SHODAN_API_KEY not configured"}

    if ioc_type not in ("ip", "domain"):
        return {"skipped": True, "reason": "Shodan only supports IP/domain lookups"}

    start = time.time()
    target_ip = ioc

    if ioc_type == "domain":
        resolved = await _resolve_domain(ioc)
        if not resolved:
            return {"error": f"Could not resolve domain to IP address"}
        target_ip = resolved

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{BASE}/shodan/host/{target_ip}", params={"key": api_key}
        )

        if resp.status_code != 200:
            try:
                err_body = resp.json()
                msg = err_body.get("error", f"HTTP {resp.status_code}")
            except Exception:
                msg = f"HTTP {resp.status_code}"

            if "No information available" in msg:
                return {"error": "No Shodan data found for this host"}

            # Paid host API often required — try InternetDB (free, keyless)
            fallback = await _internetdb_fallback(client, target_ip)
            if fallback:
                fallback["elapsed"] = round(time.time() - start, 2)
                fallback["note"] = (
                    f"Via Shodan InternetDB (host API returned: {msg}). "
                    "Upgrade Shodan for full host details on this IP."
                )
                if ioc_type == "domain":
                    fallback["resolved_from"] = ioc
                return fallback

            msg_l = msg.lower()
            if "membership" in msg_l or "upgrade" in msg_l or "paid" in msg_l or "subscribe" in msg_l:
                return {
                    "error": (
                        f"Shodan host lookup requires a paid Shodan plan for this IP ({msg}). "
                        "InternetDB had no public record. Try another source or upgrade at shodan.io."
                    )
                }
            return {"error": f"Shodan: {msg}"}

        data = resp.json()

    ports = data.get("ports", [])
    services = []
    for item in data.get("data", [])[:10]:
        services.append(
            {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", "unknown"),
                "version": item.get("version", ""),
            }
        )

    vulns = data.get("vulns", [])

    return {
        "ip": target_ip,
        "resolved_from": ioc if ioc_type == "domain" else None,
        "hostnames": data.get("hostnames", []),
        "open_ports": ports,
        "services": services,
        "isp": data.get("isp", "N/A"),
        "org": data.get("org", "N/A"),
        "asn": data.get("asn", "N/A"),
        "country": data.get("country_name", "N/A"),
        "city": data.get("city", "N/A"),
        "os": data.get("os", "N/A"),
        "vulnerabilities": vulns[:20] if vulns else [],
        "elapsed": round(time.time() - start, 2),
    }


async def _internetdb_fallback(client: httpx.AsyncClient, ip: str) -> dict | None:
    """Shodan InternetDB is free, keyless, and returns ports/vulns/tags for any IP."""
    try:
        resp = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "open_ports": data.get("ports", []),
            "services": [],
            "isp": "N/A",
            "org": "N/A",
            "asn": "N/A",
            "country": "N/A",
            "city": "N/A",
            "os": "N/A",
            "vulnerabilities": data.get("vulns", []),
            "tags": data.get("tags", []),
            "cpes": data.get("cpes", []),
        }
    except Exception:
        return None
