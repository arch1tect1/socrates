"""Alert ingestion and management API (Phase 2)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Body, Query

from ..agents import triage_agent
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
