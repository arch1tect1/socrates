"""L1 triage agent — Phase 3 will implement tool-calling loop."""

from __future__ import annotations

import logging
from uuid import UUID

logger = logging.getLogger("socrates.triage_agent")


def investigate(alert_id: UUID | str) -> None:
    """
    Fire-and-forget entry point after alert ingest.
    Phase 3: run enrichment + agent loop and write to `verdicts`.
    """
    logger.info("triage_agent.investigate (stub) alert_id=%s", alert_id)
