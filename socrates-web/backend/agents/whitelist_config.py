"""IOC whitelist for triage early-exit (tunable via env)."""

from __future__ import annotations

import os

from ..models.alerts import ExtractedIOC

_DEFAULT_DOMAINS = (
    "microsoft.com",
    "google.com",
    "github.com",
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "apple.com",
    "office.com",
    "windows.net",
    "googleapis.com",
)

_DEFAULT_IPS = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
    }
)


def whitelist_domain_suffixes() -> frozenset[str]:
    """Normalized domain suffixes (no leading dot). Env extends defaults."""
    base = {d.lower().strip(".") for d in _DEFAULT_DOMAINS}
    raw = os.getenv("SOCrates_IOC_WHITELIST_DOMAINS", "").strip()
    if not raw:
        return frozenset(base)
    extra = {p.strip().lower().strip(".") for p in raw.split(",") if p.strip()}
    return frozenset(base | extra)


def whitelist_ips() -> frozenset[str]:
    base = set(_DEFAULT_IPS)
    raw = os.getenv("SOCrates_IOC_WHITELIST_IPS", "").strip()
    if not raw:
        return frozenset(base)
    extra = {p.strip().lower() for p in raw.split(",") if p.strip()}
    return frozenset(base | extra)


def is_ioc_whitelisted(ioc: ExtractedIOC) -> bool:
    """True if this IOC is considered trusted (DNS resolvers, known SaaS domains, etc.)."""
    t = (ioc.ioc_type or "").lower()
    val = (ioc.ioc_value or "").strip().lower()
    if not val:
        return False
    if t == "domain":
        v = val.rstrip(".")
        for s in whitelist_domain_suffixes():
            if v == s or v.endswith("." + s):
                return True
        return False
    if t == "ip":
        return val in whitelist_ips()
    return False
