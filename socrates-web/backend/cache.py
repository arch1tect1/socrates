"""Supabase cache layer for IOC analysis results."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from .skip_reasons import skip_reason_for_source

logger = logging.getLogger("socrates.cache")

_client = None

SOURCE_KEY_MAP = {
    "VirusTotal": "virustotal",
    "Shodan": "shodan",
    "AbuseIPDB": "abuseipdb",
    "OTX AlienVault": "otx",
    "URLScan.io": "urlscan",
}

SOURCE_KEY_REVERSE = {v: k for k, v in SOURCE_KEY_MAP.items()}


def _get_client():
    global _client
    if _client is not None:
        return _client

    url = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")

    if not url or not key:
        logger.info("Supabase not configured — caching disabled")
        return None

    try:
        from supabase import create_client
        _client = create_client(url, key)
        logger.info("Supabase cache client initialised")
        return _client
    except Exception as e:
        logger.warning(f"Failed to create Supabase client: {e}")
        return None


async def check_cache(ioc_value: str) -> dict | None:
    """Return cached result for an IOC if it exists and hasn't expired."""
    sb = _get_client()
    if sb is None:
        return None

    try:
        now = datetime.now(timezone.utc).isoformat()
        clean = ioc_value.lower().strip()

        res = (
            sb.table("ioc_queries")
            .select("*, enrichment_results(*), ai_verdicts(*)")
            .eq("ioc_value", clean)
            .gt("expires_at", now)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )

        rows = res.data
        if not rows:
            return None

        row = rows[0]
        enrichments = row.get("enrichment_results", [])
        verdicts = row.get("ai_verdicts", [])

        sources = []
        enrichment_data = {}
        ioc_t = row.get("ioc_type", "")
        for er in enrichments:
            display_name = SOURCE_KEY_REVERSE.get(er["source"], er["source"])
            entry = {
                "source": display_name,
                "status": er["status"],
                "elapsed": er.get("response_time_seconds"),
                "error": None,
            }
            if er["status"] == "skipped":
                entry["skip_reason"] = skip_reason_for_source(display_name, ioc_t)
            sources.append(entry)
            if er["status"] == "complete" and er.get("data"):
                enrichment_data[display_name] = er["data"]

        verdict_data = None
        if verdicts:
            v = verdicts[0]
            verdict_data = {
                "verdict": v["verdict"],
                "confidence": v["confidence"],
                "reasoning": v.get("reasoning", ""),
                "key_findings": v.get("key_findings", []),
                "mitre_attack": v.get("mitre_attack", []),
                "recommended_actions": v.get("recommended_actions", []),
            }

        return {
            "query_id": row["id"],
            "ioc": row["ioc_value"],
            "ioc_type": row["ioc_type"],
            "sources": sources,
            "enrichments": enrichment_data,
            "verdict": verdict_data,
            "total_elapsed": row.get("total_time_seconds"),
            "created_at": row["created_at"],
            "cached": True,
        }

    except Exception as e:
        logger.warning(f"Cache check failed: {e}")
        return None


async def save_results(
    ioc_value: str,
    ioc_type: str,
    source_results: list[dict[str, Any]],
    enrichment_data: dict[str, Any],
    ai_verdict: dict[str, Any],
    total_time: float,
    session_id: str | None = None,
) -> str | None:
    """Persist analysis results to Supabase. Returns query_id on success."""
    sb = _get_client()
    if sb is None:
        return None

    try:
        clean = ioc_value.lower().strip()

        ttl_hours = 24
        v = ai_verdict.get("verdict", "")
        c = ai_verdict.get("confidence", "")
        if v == "MALICIOUS" and c == "HIGH":
            ttl_hours = 48
        elif v == "INCONCLUSIVE":
            ttl_hours = 6

        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

        insert_row: dict[str, Any] = {
            "ioc_value": clean,
            "ioc_type": ioc_type,
            "verdict": ai_verdict.get("verdict"),
            "confidence": ai_verdict.get("confidence"),
            "total_time_seconds": total_time,
            "expires_at": expires,
        }
        if session_id:
            insert_row["session_id"] = session_id

        query_res = sb.table("ioc_queries").insert(insert_row).execute()

        query_id = query_res.data[0]["id"]

        enrichment_rows = []
        for sr in source_results:
            db_source = SOURCE_KEY_MAP.get(sr["source"], sr["source"].lower())
            data_payload = enrichment_data.get(sr["source"], {})
            enrichment_rows.append({
                "query_id": query_id,
                "source": db_source,
                "status": sr["status"],
                "response_time_seconds": sr.get("elapsed", 0),
                "data": data_payload,
            })

        if enrichment_rows:
            sb.table("enrichment_results").insert(enrichment_rows).execute()

        sb.table("ai_verdicts").insert({
            "query_id": query_id,
            "verdict": ai_verdict.get("verdict", "INCONCLUSIVE"),
            "confidence": ai_verdict.get("confidence", "LOW"),
            "reasoning": ai_verdict.get("reasoning", ""),
            "key_findings": ai_verdict.get("key_findings", []),
            "mitre_attack": ai_verdict.get("mitre_attack", []),
            "recommended_actions": ai_verdict.get("recommended_actions", []),
            "model_used": ai_verdict.get("model_used", "claude-sonnet-4-20250514"),
        }).execute()

        logger.info(f"Cached results for {clean} (query_id={query_id}, ttl={ttl_hours}h)")
        return query_id

    except Exception as e:
        logger.warning(f"Failed to save results: {e}")
        return None


async def get_history(limit: int = 20, session_id: str | None = None) -> list[dict]:
    """Return recent IOC queries for this browser session only."""
    sb = _get_client()
    if sb is None:
        return []

    if not session_id or not session_id.strip():
        return []

    try:
        now = datetime.now(timezone.utc).isoformat()
        res = (
            sb.table("ioc_queries")
            .select("id, ioc_value, ioc_type, verdict, confidence, created_at, expires_at")
            .eq("session_id", session_id.strip())
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        items = []
        for row in res.data or []:
            is_fresh = row.get("expires_at", "") > now
            items.append({
                "id": row["id"],
                "ioc": row["ioc_value"],
                "type": row["ioc_type"],
                "verdict": row.get("verdict"),
                "confidence": row.get("confidence"),
                "created_at": row["created_at"],
                "cached": is_fresh,
            })
        return items

    except Exception as e:
        logger.warning(f"Failed to load history: {e}")
        return []
