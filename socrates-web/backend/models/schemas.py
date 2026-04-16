from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_BENIGN = "LIKELY BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AnalyzeRequest(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2048)
    force: bool = False
    session_id: Optional[str] = Field(None, max_length=128)


class SourceStatus(str, Enum):
    PENDING = "pending"
    QUERYING = "querying"
    COMPLETE = "complete"
    ERROR = "error"
    SKIPPED = "skipped"


class EnrichmentResult(BaseModel):
    source: str
    status: SourceStatus
    data: dict[str, Any] = {}
    error: Optional[str] = None
    elapsed_seconds: Optional[float] = None


class MitreAttack(BaseModel):
    technique_id: str
    technique_name: str
    relevance: str


class KeyFinding(BaseModel):
    finding: str
    severity: str
    source: str


class AIVerdict(BaseModel):
    verdict: Verdict
    confidence: Confidence
    reasoning: str
    mitre_attack: list[MitreAttack] = []
    recommended_actions: list[str] = []
    key_findings: list[KeyFinding] = []


class AnalysisResponse(BaseModel):
    ioc: str
    ioc_type: IOCType
    enrichments: list[EnrichmentResult]
    ai_verdict: Optional[AIVerdict] = None
    total_elapsed_seconds: float
