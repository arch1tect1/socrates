"""Prometheus metrics for SOCrates bot."""

from __future__ import annotations

import logging
import os

from prometheus_client import Counter, Gauge, start_http_server

logger = logging.getLogger("soc_copilot.metrics")

analyses_total = Counter(
    "socrates_analyses_total", "Total analyses performed", ["ioc_type"]
)
verdicts_total = Counter(
    "socrates_verdicts_total", "Verdict distribution", ["verdict"]
)
feedback_total = Counter(
    "socrates_feedback_total", "Analyst feedback count", ["feedback_type"]
)
users_total = Gauge("socrates_users_total", "Total registered users")
users_active_7d = Gauge("socrates_users_active_7d", "Users active in the last 7 days")


def start_metrics_server() -> None:
    """Start the Prometheus HTTP metrics endpoint (non-blocking)."""
    port = int(os.getenv("METRICS_PORT", "9090"))
    try:
        start_http_server(port)
        logger.info("Prometheus metrics server on port %d", port)
    except OSError as e:
        logger.warning("Could not start metrics server on port %d: %s", port, e)
