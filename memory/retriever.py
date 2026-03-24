"""Find similar past decisions for LLM context."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from prompts.load import load_past_decisions_footer

from .models import DecisionRecord
from .store import load_all_decisions


def _enrichment_summary_from_entry(entry: dict[str, Any]) -> dict[str, Any]:
    vt = entry.get("virustotal") or {}
    abuse = entry.get("abuseipdb") or {}
    stats = vt.get("last_analysis_stats") or {}
    mal = sus = 0
    if isinstance(stats, dict):
        mal = int(stats.get("malicious") or 0)
        sus = int(stats.get("suspicious") or 0)
    tags = vt.get("tags") if isinstance(vt.get("tags"), list) else []
    return {
        "vt_malicious": mal,
        "vt_suspicious": sus,
        "abuse_score": abuse.get("abuseConfidenceScore") if isinstance(abuse, dict) else None,
        "tags": [str(t) for t in tags[:20]],
        "as_owner": str(vt.get("as_owner", "") or ""),
        "country": str(abuse.get("countryCode", "") or "") if isinstance(abuse, dict) else "",
    }


def find_similar_decisions(
    data_dir: Path,
    chat_id: int,
    ioc_type: str,
    ioc_value: str,
    enrichment_entry: dict[str, Any],
    limit: int = 3,
) -> list[DecisionRecord]:
    all_d = load_all_decisions(data_dir, chat_id)
    if not all_d:
        return []

    vt = enrichment_entry.get("virustotal") or {}
    abuse = enrichment_entry.get("abuseipdb") or {}
    current_as = str(vt.get("as_owner", "") or "").lower()
    _tags = vt.get("tags") or []
    if isinstance(_tags, list):
        current_tags = {str(t).lower() for t in _tags}
    else:
        current_tags = set()

    scored: list[tuple[int, DecisionRecord]] = []
    for d in all_d:
        if d.ioc_value == ioc_value and d.ioc_type == ioc_type:
            scored.append((100, d))
            continue
        score = 0
        past = d.enrichment_summary or {}
        past_as = str(past.get("as_owner", "") or "").lower()
        if current_as and past_as and current_as == past_as:
            score += 50
        past_tags = {str(t).lower() for t in (past.get("tags") or [])}
        if current_tags & past_tags:
            score += 30
        if ioc_type == "ip" and d.ioc_type == "ip":
            try:
                a = ipaddress.ip_address(ioc_value)
                b = ipaddress.ip_address(d.ioc_value)
                if a.version == b.version == 4:
                    na = ipaddress.ip_network(f"{ioc_value}/24", strict=False)
                    nb = ipaddress.ip_network(f"{d.ioc_value}/24", strict=False)
                    if na.network_address == nb.network_address:
                        score += 40
            except ValueError:
                pass
        if score > 0:
            scored.append((score, d))

    scored.sort(key=lambda x: x[0], reverse=True)
    out: list[DecisionRecord] = []
    seen: set[str] = set()
    for _, d in scored:
        if d.id not in seen:
            seen.add(d.id)
            out.append(d)
        if len(out) >= limit:
            break
    return out


def format_past_decisions_for_llm(records: list[DecisionRecord]) -> str:
    if not records:
        return ""
    lines = [
        "PAST DECISIONS (similar IOCs analyzed by this team):",
        "",
    ]
    for i, d in enumerate(records, 1):
        lines.append(
            f"{i}. [{d.timestamp[:10]}] {d.ioc_type} {d.ioc_value} "
            f"(verdict in file: {d.ai_verdict or 'n/a'})"
        )
        lines.append(f"   → Analyst feedback: {d.analyst_feedback or 'none recorded'}")
        if d.analyst_note:
            lines.append(f"   → Note: {d.analyst_note}")
        if d.analyst_action_taken:
            lines.append(f"   → Action: {d.analyst_action_taken}")
        lines.append("")
    lines.append(load_past_decisions_footer())
    return "\n".join(lines)


def build_enrichment_summary(entry: dict[str, Any]) -> dict[str, Any]:
    return _enrichment_summary_from_entry(entry)
