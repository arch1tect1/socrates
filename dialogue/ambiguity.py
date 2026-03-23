"""Detect ambiguous enrichment scenarios before final LLM verdict."""

from __future__ import annotations

from typing import Any

CLOUD_KEYWORDS = (
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "cloudflare",
    "akamai",
    "fastly",
    "digitalocean",
    "oracle",
    "gcp",
)


def detect_ambiguity(
    entry: dict[str, Any],
    org_profile: dict[str, Any] | None,
) -> list[str]:
    flags: list[str] = []
    kind = entry.get("kind") or ""
    vt = entry.get("virustotal") or {}
    abuse = entry.get("abuseipdb") or {}

    if vt.get("error"):
        return []

    if kind == "ip":
        org_name = str(vt.get("as_owner", "")).lower()
        isp = ""
        if isinstance(abuse, dict) and not abuse.get("error"):
            isp = str(abuse.get("isp", "") or "").lower()
        blob = f"{org_name} {isp}"
        if any(kw in blob for kw in CLOUD_KEYWORDS):
            flags.append("CLOUD_PROVIDER_IP")

    stats = vt.get("last_analysis_stats") or {}
    if isinstance(stats, dict):
        malicious = int(stats.get("malicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        if malicious > 0 and harmless > malicious:
            flags.append("MIXED_REPUTATION")

    vt_tags = vt.get("tags") or []
    if isinstance(vt_tags, list):
        tag_l = [str(t).lower() for t in vt_tags]
        if any("tor" in t for t in tag_l):
            flags.append("TOR_EXIT_NODE")

    if entry.get("org_match") in ("NEVER_BLOCK", "OWN_INFRA"):
        flags.append("ORG_PROTECTED_IP")

    if isinstance(abuse, dict) and not abuse.get("error"):
        usage = str(abuse.get("usageType", "") or "").lower()
        if any(kw in usage for kw in ("vpn", "proxy", "hosting")):
            flags.append("VPN_PROXY")

        score = abuse.get("abuseConfidenceScore")
        if isinstance(score, (int, float)) and 20 < score < 60:
            flags.append("LOW_CONFIDENCE")

    return flags


def first_enriched_entry(payload: dict[str, Any]) -> dict[str, Any] | None:
    for e in payload.get("ioc_entries") or []:
        if e.get("enrichment_skipped") or e.get("error"):
            continue
        if e.get("virustotal", {}).get("error") and not e.get("abuseipdb"):
            continue
        return e
    return None
