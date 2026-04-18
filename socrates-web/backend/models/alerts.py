"""Pydantic models for alert ingestion and API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
AlertStatus = Literal["open", "investigating", "resolved", "false_positive", "escalated"]
IOCType = Literal["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"]
VerdictKind = Literal["malicious", "suspicious", "benign", "inconclusive"]


class ExtractedIOC(BaseModel):
    ioc_type: IOCType
    ioc_value: str
    extracted_from: Optional[str] = None


class AlertCreate(BaseModel):
    source: str
    source_alert_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Severity
    title: str
    description: Optional[str] = None
    raw_payload: dict[str, Any]


class VerdictResponse(BaseModel):
    id: UUID
    verdict: VerdictKind
    confidence: float
    reasoning: str
    tools_used: list[dict[str, Any]]
    recommended_action: Optional[str]
    agent_trace: list[dict[str, Any]]
    created_at: datetime


class AlertResponse(BaseModel):
    id: UUID
    source: str
    rule_name: Optional[str] = None
    severity: Severity
    status: AlertStatus
    title: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    iocs: list[ExtractedIOC] = Field(default_factory=list)
    verdict: Optional[VerdictResponse] = None


class ManualSubmitRequest(BaseModel):
    raw_text: str = Field(..., min_length=1, max_length=1_000_000)
    source_label: str = Field(default="manual", max_length=256)
    title: Optional[str] = Field(default=None, max_length=512)
    severity: Optional[Severity] = None


class StatusPatchRequest(BaseModel):
    status: AlertStatus
