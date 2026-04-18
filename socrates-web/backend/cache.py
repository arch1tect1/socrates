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


def _debug_supabase_enabled() -> bool:
    return os.getenv("SOCRATES_SUPABASE_DEBUG", "").strip().lower() in ("1", "true", "yes")


def _log_supabase_env() -> None:
    """Safe diagnostics (never log secrets)."""
    if not _debug_supabase_enabled():
        return
    url = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL") or ""
    try:
        from urllib.parse import urlparse

        host = urlparse(url).netloc or "(invalid URL)"
    except Exception:
        host = "(could not parse URL)"
    has_service = bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
    has_anon = bool(os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY"))
    logger.info(
        "SOCRATES_SUPABASE_DEBUG: host=%s SUPABASE_SERVICE_ROLE_KEY=%s NEXT_PUBLIC_SUPABASE_ANON_KEY=%s",
        host,
        "set" if has_service else "missing",
        "set" if has_anon else "missing",
    )


def _format_db_exception(exc: BaseException) -> str:
    parts = [f"{type(exc).__name__}: {exc}"]
    for attr in ("message", "details", "hint", "code"):
        if hasattr(exc, attr):
            val = getattr(exc, attr)
            if val is not None and str(val) and str(val) not in parts[0]:
                parts.append(f"{attr}={val!r}")
    if getattr(exc, "args", None) and isinstance(exc.args[0], dict):
        parts.append(f"payload={exc.args[0]!r}")
    return " | ".join(parts)


def _get_client():
    global _client
    if _client is not None:
        return _client

    _log_supabase_env()

    url = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    service = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    key = service or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")

    if not url or not key:
        logger.warning(
            "Supabase not configured — caching disabled "
            "(need SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY or NEXT_PUBLIC_SUPABASE_ANON_KEY)"
        )
        return None

    if not service:
        logger.warning(
            "Supabase: SUPABASE_SERVICE_ROLE_KEY is not set; using anon key. "
            "Inserts usually fail when Row Level Security is enabled on ioc_queries. "
            "Set SUPABASE_SERVICE_ROLE_KEY on the server (Vercel env). "
            "Never expose the service role in NEXT_PUBLIC_* or frontend bundles."
        )

    try:
        from supabase import create_client

        _client = create_client(url, key)
        logger.info(
            "Supabase cache client initialised (%s)",
            "service_role" if service else "anon_key_fallback",
        )
        return _client
    except Exception as e:
        logger.error("Failed to create Supabase client: %s", _format_db_exception(e), exc_info=True)
        return None


def get_supabase_client():
    """Return the shared Supabase client (or None if not configured). Used by cache and alerts."""
    return _get_client()


def get_cached_enrichment_for_source(ioc_value: str, source_db_key: str) -> dict | None:
    """
    Return enrichment payload for one source if a non-expired ioc_queries row exists
    with a complete enrichment_results row (Phase 3 triage tool cache).
    """
    sb = _get_client()
    if sb is None:
        return None

    try:
        now = datetime.now(timezone.utc).isoformat()
        clean = ioc_value.lower().strip()

        qres = (
            sb.table("ioc_queries")
            .select("id")
            .eq("ioc_value", clean)
            .gt("expires_at", now)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = qres.data or []
        if not rows:
            return None

        query_id = rows[0]["id"]
        eres = (
            sb.table("enrichment_results")
            .select("data, status")
            .eq("query_id", query_id)
            .eq("source", source_db_key)
            .eq("status", "complete")
            .limit(1)
            .execute()
        )
        erows = eres.data or []
        if not erows or not erows[0].get("data"):
            return None

        return {"cached": True, "data": erows[0]["data"], "query_id": str(query_id)}
    except Exception as e:
        logger.warning("get_cached_enrichment_for_source failed: %s", _format_db_exception(e))
        return None


def save_tool_enrichment_to_cache(
    ioc_value: str,
    ioc_type_db: str,
    source_db_key: str,
    data: dict[str, Any],
    elapsed: float,
) -> None:
    """
    Persist a single-source enrichment into ioc_queries + enrichment_results so later
    triage runs can skip external API calls within the TTL window.
    """
    sb = _get_client()
    if sb is None:
        return

    clean = ioc_value.lower().strip()
    ttl_hours = 24
    expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

    try:
        now = datetime.now(timezone.utc).isoformat()
        qres = (
            sb.table("ioc_queries")
            .select("id")
            .eq("ioc_value", clean)
            .gt("expires_at", now)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = qres.data or []
        if rows:
            query_id = rows[0]["id"]
        else:
            insert_row: dict[str, Any] = {
                "ioc_value": clean,
                "ioc_type": ioc_type_db,
                "verdict": "INCONCLUSIVE",
                "confidence": "LOW",
                "total_time_seconds": round(elapsed, 2),
                "expires_at": expires,
            }
            ins = sb.table("ioc_queries").insert(insert_row).execute()
            ins_rows = ins.data or []
            if not ins_rows:
                logger.warning("save_tool_enrichment_to_cache: ioc_queries insert failed for %r", clean)
                return
            query_id = ins_rows[0]["id"]

        existing = (
            sb.table("enrichment_results")
            .select("id")
            .eq("query_id", query_id)
            .eq("source", source_db_key)
            .limit(1)
            .execute()
        )
        erow = {
            "query_id": query_id,
            "source": source_db_key,
            "status": "complete",
            "response_time_seconds": round(elapsed, 2),
            "data": data,
        }
        if existing.data:
            sb.table("enrichment_results").update(
                {
                    "status": "complete",
                    "response_time_seconds": round(elapsed, 2),
                    "data": data,
                }
            ).eq("id", existing.data[0]["id"]).execute()
        else:
            sb.table("enrichment_results").insert(erow).execute()

        logger.info(
            "save_tool_enrichment_to_cache: source=%s ioc=%s query_id=%s",
            source_db_key,
            clean,
            query_id,
        )
    except Exception as e:
        logger.warning("save_tool_enrichment_to_cache failed: %s", _format_db_exception(e))


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
        logger.warning("Cache check failed: %s", _format_db_exception(e))
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
        logger.warning(
            "save_results: skipped persist for ioc=%r — Supabase client unavailable",
            ioc_value[:120] if ioc_value else "",
        )
        return None

    clean = ioc_value.lower().strip()
    logger.info(
        "save_results: start ioc_value=%s ioc_type=%s session_id=%s sources=%d",
        clean,
        ioc_type,
        "set" if (session_id and session_id.strip()) else "none",
        len(source_results),
    )

    try:
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
            insert_row["session_id"] = session_id.strip()

        query_res = sb.table("ioc_queries").insert(insert_row).execute()
        rows = query_res.data if query_res.data is not None else []
        if not rows:
            logger.error(
                "save_results: ioc_queries INSERT returned no row (check RLS, column session_id, or schema). "
                "response=%r",
                getattr(query_res, "data", None),
            )
            return None

        query_id = rows[0]["id"]
        logger.info("save_results: ioc_queries row created query_id=%s", query_id)

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
            try:
                sb.table("enrichment_results").insert(enrichment_rows).execute()
                logger.info(
                    "save_results: enrichment_results inserted count=%d",
                    len(enrichment_rows),
                )
            except Exception as e:
                logger.error(
                    "save_results: enrichment_results INSERT failed: %s",
                    _format_db_exception(e),
                    exc_info=True,
                )
                try:
                    sb.table("ioc_queries").delete().eq("id", query_id).execute()
                except Exception as rollback_exc:
                    logger.warning(
                        "save_results: rollback ioc_queries %s failed: %s",
                        query_id,
                        _format_db_exception(rollback_exc),
                    )
                return None

        try:
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
            logger.info("save_results: ai_verdicts row created query_id=%s", query_id)
        except Exception as e:
            logger.error(
                "save_results: ai_verdicts INSERT failed: %s",
                _format_db_exception(e),
                exc_info=True,
            )
            try:
                sb.table("ioc_queries").delete().eq("id", query_id).execute()
            except Exception as rollback_exc:
                logger.warning(
                    "save_results: rollback ioc_queries %s failed: %s",
                    query_id,
                    _format_db_exception(rollback_exc),
                )
            return None

        logger.info(
            "save_results: OK query_id=%s ioc=%s ttl=%sh (Supabase cache + history complete)",
            query_id,
            clean,
            ttl_hours,
        )
        return query_id

    except Exception as e:
        msg = str(e).lower()
        formatted = _format_db_exception(e)
        if "row-level security" in msg or "rls" in msg or "42501" in msg or "permission denied" in msg:
            logger.error(
                "save_results: RLS/permission denied — %s. "
                "Set SUPABASE_SERVICE_ROLE_KEY on Vercel, or add INSERT policies / disable RLS. "
                "See sql/fix_cache_writes_rls.sql",
                formatted,
                exc_info=True,
            )
        elif "session_id" in msg and ("column" in msg or "does not exist" in msg):
            logger.error(
                "save_results: schema error — %s. Run sql/add_session_id.sql (or add_session_id + index).",
                formatted,
                exc_info=True,
            )
        else:
            logger.error("save_results: failed — %s", formatted, exc_info=True)
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
        logger.warning("Failed to load history: %s", _format_db_exception(e))
        return []
