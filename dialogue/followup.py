"""Generate follow-up questions and preliminary text for ambiguous IOCs."""

from __future__ import annotations

from typing import Any

from prompts.load import load_followup_questions

FOLLOWUP_MAP: dict[str, list[str]] = load_followup_questions()


def generate_followups(flags: list[str], entry: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    questions: list[str] = []
    vt = entry.get("virustotal") or {}
    stats = vt.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0) if isinstance(stats, dict) else 0
    harm = int(stats.get("harmless") or 0) if isinstance(stats, dict) else 0
    abuse = entry.get("abuseipdb") or {}
    score = abuse.get("abuseConfidenceScore") if isinstance(abuse, dict) else None

    for flag in flags:
        for q in FOLLOWUP_MAP.get(flag, []):
            if flag == "MIXED_REPUTATION" and "{malicious}" not in q:
                q = q.replace(
                    "Reputation data is mixed",
                    f"Reputation data is mixed — {mal} vendors flag malicious, {harm} say clean.",
                )
            if flag == "LOW_CONFIDENCE" and score is not None:
                q = q.replace(
                    "moderate abuse score",
                    f"abuse score: {score}/100",
                )
            if q not in seen:
                seen.add(q)
                questions.append(q)
    return questions[:8]


def format_preliminary(entry: dict[str, Any], flags: list[str]) -> str:
    vt = entry.get("virustotal") or {}
    abuse = entry.get("abuseipdb") or {}
    lines = [
        "<b>Preliminary enrichment</b>",
        f"IOC: <code>{entry.get('ioc', '')}</code> ({entry.get('kind', '')})",
    ]
    if isinstance(vt, dict) and not vt.get("error"):
        stats = vt.get("last_analysis_stats") or {}
        lines.append(f"VirusTotal stats: {stats}")
        if vt.get("as_owner"):
            lines.append(f"AS / network: {vt.get('as_owner')}")
    if isinstance(abuse, dict) and not abuse.get("error"):
        lines.append(
            f"AbuseIPDB score: {abuse.get('abuseConfidenceScore')} | "
            f"ISP: {abuse.get('isp')}"
        )
    lines.append("")
    lines.append(f"<b>Ambiguity flags</b>: {', '.join(flags)}")
    return "\n".join(lines)
