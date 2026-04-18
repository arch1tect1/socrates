"""Maps triage tool names to enrichment services with ioc_queries cache-first behavior."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..cache import get_cached_enrichment_for_source, get_supabase_client, save_tool_enrichment_to_cache
from ..enrichment import abuseipdb, otx, shodan, urlscan, virustotal

logger = logging.getLogger("socrates.tool_executor")

# enrichment_results.source values (matches cache.SOURCE_KEY_MAP values)
SRC_VT = "virustotal"
SRC_SHODAN = "shodan"
SRC_ABUSE = "abuseipdb"
SRC_OTX = "otx"
SRC_URLSCAN = "urlscan"
SRC_WHOIS = "whois"


def tool_ioc_type_to_enrichment(ioc_type: str) -> str:
    t = (ioc_type or "").lower().strip()
    if t in ("hash_md5", "hash_sha1", "hash_sha256", "md5", "sha1", "sha256", "hash"):
        return "hash"
    return t if t else "ip"


class ToolExecutor:
    """Execute triage tools; prefer Supabase enrichment cache (<24h) before external APIs."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {
            "check_virustotal": self._check_vt,
            "check_shodan": self._check_shodan,
            "check_abuseipdb": self._check_abuse,
            "check_otx": self._check_otx,
            "scan_url": self._scan_url,
            "get_whois": self._get_whois,
            "search_similar_alerts": self._search_similar,
        }

    async def execute(self, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
        handler = self.handlers.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return await handler(**tool_input)
        except TypeError as e:
            return {"error": f"Invalid arguments for {tool_name}: {e}", "tool": tool_name}
        except Exception as e:
            logger.exception("tool %s failed", tool_name)
            return {"error": str(e), "tool": tool_name}

    async def _maybe_cache(
        self,
        ioc_value: str,
        ioc_type_db: str,
        source_key: str,
        fresh: dict[str, Any],
        elapsed: float,
    ) -> dict[str, Any]:
        """Attach fresh API result to cache; strip internal elapsed if present."""
        save_tool_enrichment_to_cache(ioc_value, ioc_type_db, source_key, fresh, elapsed)
        out = dict(fresh)
        out["cached"] = False
        return out

    async def _check_vt(self, ioc_value: str, ioc_type: str) -> dict[str, Any]:
        et = tool_ioc_type_to_enrichment(ioc_type)
        hit = get_cached_enrichment_for_source(ioc_value, SRC_VT)
        if hit:
            d = dict(hit["data"])
            d["cached"] = True
            return d

        raw = await virustotal.query(ioc_value, et)
        elapsed = float(raw.pop("elapsed", 0.0))
        if raw.get("error") or raw.get("skipped"):
            return raw
        return await self._maybe_cache(ioc_value, et, SRC_VT, raw, elapsed)

    async def _check_shodan(self, ip: str) -> dict[str, Any]:
        hit = get_cached_enrichment_for_source(ip, SRC_SHODAN)
        if hit:
            d = dict(hit["data"])
            d["cached"] = True
            return d

        raw = await shodan.query(ip, "ip")
        elapsed = float(raw.pop("elapsed", 0.0))
        if raw.get("error") or raw.get("skipped"):
            return raw
        return await self._maybe_cache(ip, "ip", SRC_SHODAN, raw, elapsed)

    async def _check_abuse(self, ip: str) -> dict[str, Any]:
        hit = get_cached_enrichment_for_source(ip, SRC_ABUSE)
        if hit:
            d = dict(hit["data"])
            d["cached"] = True
            return d

        raw = await abuseipdb.query(ip, "ip")
        elapsed = float(raw.pop("elapsed", 0.0))
        if raw.get("error") or raw.get("skipped"):
            return raw
        return await self._maybe_cache(ip, "ip", SRC_ABUSE, raw, elapsed)

    async def _check_otx(self, ioc_value: str, ioc_type: str) -> dict[str, Any]:
        et = tool_ioc_type_to_enrichment(ioc_type)
        hit = get_cached_enrichment_for_source(ioc_value, SRC_OTX)
        if hit:
            d = dict(hit["data"])
            d["cached"] = True
            return d

        raw = await otx.query(ioc_value, et)
        elapsed = float(raw.pop("elapsed", 0.0))
        if raw.get("error") or raw.get("skipped"):
            return raw
        return await self._maybe_cache(ioc_value, et, SRC_OTX, raw, elapsed)

    async def _scan_url(self, url: str) -> dict[str, Any]:
        hit = get_cached_enrichment_for_source(url, SRC_URLSCAN)
        if hit:
            d = dict(hit["data"])
            d["cached"] = True
            return d

        raw = await urlscan.query(url, "url")
        elapsed = float(raw.pop("elapsed", 0.0))
        if raw.get("error") or raw.get("skipped"):
            return raw
        return await self._maybe_cache(url, "url", SRC_URLSCAN, raw, elapsed)

    async def _get_whois(self, domain: str) -> dict[str, Any]:
        d = domain.strip().lower()
        hit = get_cached_enrichment_for_source(d, SRC_WHOIS)
        if hit:
            out = dict(hit["data"])
            out["cached"] = True
            return out

        start = datetime.now(timezone.utc)
        rdap = await _rdap_domain(d)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        if rdap.get("error"):
            return rdap
        return await self._maybe_cache(d, "domain", SRC_WHOIS, rdap, elapsed)

    async def _search_similar(
        self,
        ioc_value: str | None = None,
        rule_pattern: str | None = None,
    ) -> dict[str, Any]:
        sb = get_supabase_client()
        if sb is None:
            return {"error": "Supabase not configured", "matches": []}

        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        matches: list[dict[str, Any]] = []

        try:
            if ioc_value and ioc_value.strip():
                clean = ioc_value.strip().lower()
                ioc_rows = (
                    sb.table("alert_iocs")
                    .select("alert_id")
                    .eq("ioc_value", clean)
                    .gte("created_at", cutoff)
                    .limit(50)
                    .execute()
                )
                alert_ids = list({r["alert_id"] for r in (ioc_rows.data or [])})
                for aid in alert_ids[:20]:
                    ares = (
                        sb.table("alerts")
                        .select("id, title, rule_name, severity, status, created_at")
                        .eq("id", aid)
                        .limit(1)
                        .execute()
                    )
                    for row in ares.data or []:
                        matches.append(
                            {
                                "alert_id": str(row["id"]),
                                "title": row.get("title"),
                                "rule_name": row.get("rule_name"),
                                "severity": row.get("severity"),
                                "status": row.get("status"),
                                "created_at": row.get("created_at"),
                                "match": "ioc",
                            }
                        )

            if rule_pattern and rule_pattern.strip():
                pat = rule_pattern.strip()
                q = (
                    sb.table("alerts")
                    .select("id, title, rule_name, severity, status, created_at")
                    .gte("created_at", cutoff)
                    .limit(30)
                    .execute()
                )
                for row in q.data or []:
                    rn = (row.get("rule_name") or "") + " " + (row.get("title") or "")
                    if pat.lower() in rn.lower():
                        matches.append(
                            {
                                "alert_id": str(row["id"]),
                                "title": row.get("title"),
                                "rule_name": row.get("rule_name"),
                                "severity": row.get("severity"),
                                "status": row.get("status"),
                                "created_at": row.get("created_at"),
                                "match": "rule_pattern",
                            }
                        )

            # Dedupe by alert_id
            seen: set[str] = set()
            uniq: list[dict[str, Any]] = []
            for m in matches:
                aid = m.get("alert_id")
                if not aid or aid in seen:
                    continue
                seen.add(aid)
                uniq.append(m)

            return {"matches": uniq[:25], "cached": False}
        except Exception as e:
            logger.warning("search_similar_alerts failed: %s", e)
            return {"error": str(e), "matches": []}


async def _rdap_domain(domain: str) -> dict[str, Any]:
    """Fetch public RDAP summary for domain age / registrar (no extra API key)."""
    safe = re.sub(r"[^a-z0-9.\-]", "", domain.lower()).strip(".")
    if not safe or "." not in safe:
        return {"error": "invalid domain"}

    url = f"https://rdap.org/domain/{safe}"
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            resp = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
    except httpx.HTTPError as e:
        return {"error": f"RDAP request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"RDAP HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except Exception:
        return {"error": "RDAP invalid JSON"}

    events = data.get("events") or []
    reg_date = None
    for ev in events:
        if (ev.get("eventAction") or "").lower() == "registration":
            reg_date = ev.get("eventDate")
            break

    entities = data.get("entities") or []
    registrar = None
    for ent in entities:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                        registrar = item[3]
                        break
            break

    return {
        "domain": safe,
        "registration_date": reg_date,
        "registrar": registrar or "unknown",
        "status": [s.get("state") for s in (data.get("status") or []) if isinstance(s, dict)][:10],
    }
