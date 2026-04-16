"""Fallback skip explanations when enrichment modules don't return a reason."""

from __future__ import annotations

# IOC types each source handles (for UX when status is skipped but reason missing)
SOURCE_IOC_SUPPORT: dict[str, frozenset[str]] = {
    "VirusTotal": frozenset({"ip", "domain", "url", "hash"}),
    "Shodan": frozenset({"ip", "domain"}),
    "AbuseIPDB": frozenset({"ip", "domain"}),
    "OTX AlienVault": frozenset({"ip", "domain", "hash"}),
    "URLScan.io": frozenset({"domain", "url"}),
}

SKIP_FALLBACK: dict[str, str] = {
    "Shodan": "IP and domain lookups only",
    "AbuseIPDB": "IP and domain lookups only",
    "OTX AlienVault": "Not supported for this IOC type",
    "URLScan.io": "Domains and URLs only",
}


def skip_reason_for_source(source_display_name: str, ioc_type: str) -> str:
    """Short reason line for skipped sources (no leading 'Skipped —')."""
    supported = SOURCE_IOC_SUPPORT.get(source_display_name)
    if supported is None:
        return "Not supported for this IOC type"
    if ioc_type not in supported:
        return SKIP_FALLBACK.get(
            source_display_name,
            "Not supported for this IOC type",
        )
    return "Unavailable for this query"
