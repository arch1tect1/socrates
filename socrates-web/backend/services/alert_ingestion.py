"""Parse alerts, extract IOCs, persist to Supabase, return API models."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from fastapi import HTTPException

from ..cache import get_supabase_client
from ..models.alerts import (
    AlertCreate,
    AlertResponse,
    AlertStatus,
    ExtractedIOC,
    Severity,
    VerdictResponse,
)
from .alert_parser import ParserRegistry
from .ioc_extractor import IOCExtractor

logger = logging.getLogger("socrates.alert_ingestion")

registry = ParserRegistry()
extractor = IOCExtractor()


def _dedupe_iocs(iocs: list[ExtractedIOC]) -> list[ExtractedIOC]:
    seen: set[tuple[str, str]] = set()
    out: list[ExtractedIOC] = []
    for x in iocs:
        k = (x.ioc_type, x.ioc_value.lower())
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def _collect_iocs(alert: AlertCreate) -> list[ExtractedIOC]:
    parts = [alert.title, alert.description or "", json.dumps(alert.raw_payload, ensure_ascii=False)]
    blob = "\n".join(p for p in parts if p)
    from_text = extractor.extract(blob, context="alert_fields")
    from_json = extractor.extract_from_dict(alert.raw_payload)
    return _dedupe_iocs(from_text + from_json)


def _row_to_alert_response(
    row: dict[str, Any],
    iocs: list[ExtractedIOC],
    verdict: Optional[VerdictResponse],
) -> AlertResponse:
    return AlertResponse(
        id=UUID(str(row["id"])),
        source=row["source"],
        rule_name=row.get("rule_name"),
        severity=row["severity"],
        status=row["status"],
        title=row["title"],
        description=row.get("description"),
        created_at=_parse_ts(row["created_at"]),
        updated_at=_parse_ts(row["updated_at"]),
        iocs=iocs,
        verdict=verdict,
    )


def _parse_ts(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    raise ValueError(f"bad timestamp: {v!r}")


def _fetch_verdict_latest(sb: Any, alert_id: str) -> Optional[VerdictResponse]:
    res = (
        sb.table("verdicts")
        .select("*")
        .eq("alert_id", alert_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = res.data or []
    if not rows:
        return None
    v = rows[0]
    return VerdictResponse(
        id=UUID(str(v["id"])),
        verdict=v["verdict"],
        confidence=float(v["confidence"]),
        reasoning=v["reasoning"],
        tools_used=v.get("tools_used") or [],
        recommended_action=v.get("recommended_action"),
        agent_trace=v.get("agent_trace") or [],
        created_at=_parse_ts(v["created_at"]),
    )


def fetch_alert(alert_id: UUID) -> AlertResponse:
    sb = get_supabase_client()
    if sb is None:
        raise HTTPException(status_code=503, detail="Supabase not configured")

    aid = str(alert_id)
    res = sb.table("alerts").select("*").eq("id", aid).limit(1).execute()
    rows = res.data or []
    if not rows:
        raise HTTPException(status_code=404, detail="Alert not found")
    row = rows[0]

    ioc_res = sb.table("alert_iocs").select("*").eq("alert_id", aid).execute()
    iocs = [
        ExtractedIOC(
            ioc_type=r["ioc_type"],
            ioc_value=r["ioc_value"],
            extracted_from=r.get("extracted_from"),
        )
        for r in (ioc_res.data or [])
    ]
    verdict = _fetch_verdict_latest(sb, aid)
    return _row_to_alert_response(row, iocs, verdict)


def list_alerts(
    *,
    status: Optional[AlertStatus] = None,
    severity: Optional[Severity] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[AlertResponse]:
    sb = get_supabase_client()
    if sb is None:
        raise HTTPException(status_code=503, detail="Supabase not configured")

    q = sb.table("alerts").select("*")
    if status:
        q = q.eq("status", status)
    if severity:
        q = q.eq("severity", severity)
    res = (
        q.order("created_at", desc=True)
        .limit(max(1, min(limit, 200)))
        .offset(max(0, offset))
        .execute()
    )
    rows = res.data or []
    out: list[AlertResponse] = []
    for row in rows:
        aid = str(row["id"])
        ioc_res = sb.table("alert_iocs").select("*").eq("alert_id", aid).execute()
        iocs = [
            ExtractedIOC(
                ioc_type=r["ioc_type"],
                ioc_value=r["ioc_value"],
                extracted_from=r.get("extracted_from"),
            )
            for r in (ioc_res.data or [])
        ]
        verdict = _fetch_verdict_latest(sb, aid)
        out.append(_row_to_alert_response(row, iocs, verdict))
    return out


def update_alert_status(alert_id: UUID, status: AlertStatus) -> AlertResponse:
    sb = get_supabase_client()
    if sb is None:
        raise HTTPException(status_code=503, detail="Supabase not configured")

    aid = str(alert_id)
    res = (
        sb.table("alerts")
        .update({"status": status})
        .eq("id", aid)
        .select("*")
        .execute()
    )
    rows = res.data or []
    if not rows:
        raise HTTPException(status_code=404, detail="Alert not found")
    return fetch_alert(alert_id)


def ingest(
    payload: dict[str, Any],
    *,
    parser_hint: Optional[str] = None,
) -> AlertResponse:
    sb = get_supabase_client()
    if sb is None:
        raise HTTPException(status_code=503, detail="Supabase not configured — set SUPABASE_URL and key")

    try:
        alert_model = registry.parse(payload, parser_hint=parser_hint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    iocs = _collect_iocs(alert_model)
    logger.info(
        "Ingesting alert source=%s title=%r iocs=%d",
        alert_model.source,
        alert_model.title,
        len(iocs),
    )

    insert_row: dict[str, Any] = {
        "source": alert_model.source,
        "source_alert_id": alert_model.source_alert_id,
        "rule_name": alert_model.rule_name,
        "severity": alert_model.severity,
        "status": "open",
        "title": alert_model.title,
        "description": alert_model.description,
        "raw_payload": alert_model.raw_payload,
    }

    try:
        ins = sb.table("alerts").insert(insert_row).select("*").execute()
    except Exception as e:
        logger.exception("alerts insert failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Database error: {e!s}") from e

    rows = ins.data or []
    if not rows:
        raise HTTPException(status_code=500, detail="Insert returned no row")
    alert_row = rows[0]
    aid = str(alert_row["id"])

    for ioc in iocs:
        try:
            sb.table("alert_iocs").insert({
                "alert_id": aid,
                "ioc_type": ioc.ioc_type,
                "ioc_value": ioc.ioc_value,
                "extracted_from": ioc.extracted_from,
            }).execute()
        except Exception as e:
            logger.exception("alert_iocs insert failed alert_id=%s: %s", aid, e)
            try:
                sb.table("alerts").delete().eq("id", aid).execute()
            except Exception as rollback_exc:
                logger.warning("rollback failed: %s", rollback_exc)
            raise HTTPException(status_code=500, detail=f"Database error: {e!s}") from e

    return fetch_alert(UUID(aid))
