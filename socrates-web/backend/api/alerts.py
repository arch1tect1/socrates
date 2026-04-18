"""Alert ingestion and management API (Phase 2)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Body, Header, HTTPException, Query

from ..agents import triage_agent
from ..cache import get_supabase_client
from ..services.stuck_alerts import list_stuck_alerts_fallback, list_stuck_alerts_via_rpc
from ..models.alerts import (
    AlertResponse,
    AlertStatus,
    ManualSubmitRequest,
    Severity,
    StatusPatchRequest,
)
from ..services import alert_ingestion

router = APIRouter()


@router.post("/webhook/wazuh", response_model=AlertResponse)
async def wazuh_webhook(
    background_tasks: BackgroundTasks,
    payload: dict = Body(...),
) -> AlertResponse:
    """Wazuh JSON webhook — configure integration to POST this endpoint."""
    alert = alert_ingestion.ingest(payload, parser_hint="wazuh")
    background_tasks.add_task(triage_agent.investigate, alert.id)
    return alert


@router.post("/manual", response_model=AlertResponse)
async def manual_submit(
    background_tasks: BackgroundTasks,
    body: ManualSubmitRequest,
) -> AlertResponse:
    """Paste raw log / email body; IOCs are extracted automatically."""
    payload: dict = {
        "raw_text": body.raw_text,
        "source": body.source_label,
        "_force_manual": True,
    }
    if body.title is not None:
        payload["title"] = body.title
    if body.severity is not None:
        payload["severity"] = body.severity

    alert = alert_ingestion.ingest(payload, parser_hint="manual")
    background_tasks.add_task(triage_agent.investigate, alert.id)
    return alert


@router.post("/admin/reprocess-stuck")
async def reprocess_stuck_alerts(
    background_tasks: BackgroundTasks,
    older_than_minutes: int = Query(10, ge=1, le=10080),
    x_socrates_admin_secret: str | None = Header(None, alias="X-SOCrates-Admin-Secret"),
) -> dict:
    """
    Queue triage for alerts that have no verdict row and are older than the cutoff.
    Optional: set SOCRATES_ADMIN_SECRET and send the same value in header X-SOCrates-Admin-Secret.
    """
    expected = os.getenv("SOCRATES_ADMIN_SECRET", "").strip()
    if expected and (not x_socrates_admin_secret or x_socrates_admin_secret != expected):
        raise HTTPException(status_code=401, detail="Invalid or missing admin secret")

    sb = get_supabase_client()
    if sb is None:
        raise HTTPException(status_code=503, detail="Supabase not configured")

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)
    cutoff_iso = cutoff.isoformat()

    rows: list[dict] = []
    try:
        rpc_rows = list_stuck_alerts_via_rpc(sb, cutoff_iso)
        if rpc_rows is not None:
            rows = rpc_rows
        else:
            rows = list_stuck_alerts_fallback(sb, cutoff_iso)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list stuck alerts: {e!s}",
        ) from e
    ids_out: list[str] = []
    for row in rows:
        raw_id = row.get("id")
        if not raw_id:
            continue
        aid = UUID(str(raw_id))
        ids_out.append(str(aid))
        background_tasks.add_task(triage_agent.investigate, aid)

    return {"reprocessed_count": len(ids_out), "alert_ids": ids_out}


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    status: Optional[AlertStatus] = Query(None),
    severity: Optional[Severity] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[AlertResponse]:
    return alert_ingestion.list_alerts(
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: UUID) -> AlertResponse:
    return alert_ingestion.fetch_alert(alert_id)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
async def update_status(alert_id: UUID, body: StatusPatchRequest) -> AlertResponse:
    return alert_ingestion.update_alert_status(alert_id, body.status)
