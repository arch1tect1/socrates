"""Find alerts with no verdict (maintenance / reprocess-stuck)."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("socrates.stuck_alerts")


def list_stuck_alerts_via_rpc(sb: Any, cutoff_iso: str) -> list[dict] | None:
    """Return rows from RPC, or None so the caller uses the Python fallback.

    Any RPC/PostgREST error falls back — avoids brittle string matching on exception types
    and works when the DB function or grants are missing.
    """
    try:
        res = sb.rpc(
            "find_alerts_without_verdict",
            {"cutoff": cutoff_iso},
        ).execute()
        return res.data or []
    except Exception as e:
        logger.warning("find_alerts_without_verdict RPC skipped (fallback): %s", e)
        return None


def list_stuck_alerts_fallback(sb: Any, cutoff_iso: str, *, max_rows: int = 500) -> list[dict]:
    """
    Same semantics as the SQL function: alerts older than cutoff with no verdict row.
    Uses pagination (no RPC). Heavier on large DBs but works without a migration.
    """
    verdict_ids: set[str] = set()
    step = 1000
    start = 0
    while True:
        res = (
            sb.table("verdicts")
            .select("alert_id")
            .range(start, start + step - 1)
            .execute()
        )
        batch = res.data or []
        for r in batch:
            if r.get("alert_id"):
                verdict_ids.add(str(r["alert_id"]))
        if len(batch) < step:
            break
        start += step
        if start > 500_000:
            logger.warning("stuck_alerts: verdict_id scan capped at 500k rows")
            break

    out: list[dict] = []
    start = 0
    while len(out) < max_rows:
        res = (
            sb.table("alerts")
            .select("id, created_at, source")
            .lt("created_at", cutoff_iso)
            .order("created_at", desc=False)
            .range(start, start + step - 1)
            .execute()
        )
        batch = res.data or []
        for r in batch:
            rid = str(r.get("id", ""))
            if rid and rid not in verdict_ids:
                out.append(r)
                if len(out) >= max_rows:
                    break
        if len(batch) < step:
            break
        start += step
        if start > 200_000:
            logger.warning("stuck_alerts: alerts scan capped at 200k rows")
            break

    return sorted(out, key=lambda x: (x.get("created_at") or ""))[:max_rows]
