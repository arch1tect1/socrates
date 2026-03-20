"""Extract IOCs from arbitrary text, logs, or JSON-ish alerts."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

# IPv4 embedded in text
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

DOMAIN_RE = re.compile(
    r"\b(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\b"
)

# Tokens that might be IPv6 (contains colon)
IPV6_CANDIDATE = re.compile(
    r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]+(?![0-9a-fA-F:])"
)


@dataclass(frozen=True)
class ExtractedIOC:
    value: str
    kind: str  # "ip" | "domain" | "hash"


def is_public_routable_ip(ip: str) -> bool:
    """True if the address is globally routable (not RFC1918, loopback, CGNAT, etc.)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def placeholder_ioc_note(text: str) -> str | None:
    """Warn when logs still contain template placeholders instead of real IOCs."""
    t = text.strip()
    if re.search(r"\bdst\s*=\s*<[^>\s]+>", t, re.I):
        return (
            "The log still contains a destination placeholder (e.g. dst=<...>) — "
            "replace it with a real public IP from your feed before sending; "
            "otherwise only internal/private IPs may be extracted."
        )
    if re.search(r"<IP[_ ]FROM[_ ]FEED>", t, re.I) or "<IP_FROM_FEED>" in t:
        return (
            "Replace <IP_FROM_FEED> with an actual routable IP from your threat feed; "
            "placeholders are not valid indicators for VirusTotal/AbuseIPDB/Shodan."
        )
    return None


def _normalize_ip(token: str) -> str | None:
    t = token.strip().strip("[]")
    if "%" in t:
        t = t.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def extract_iocs_from_text(text: str) -> list[ExtractedIOC]:
    """Pull IPs, domains, and hashes from free-form log or JSON text."""
    if not text or not text.strip():
        return []

    sample = text
    try:
        parsed = json.loads(text)
        if isinstance(parsed, (dict, list)):
            sample = json.dumps(parsed)
    except json.JSONDecodeError:
        pass

    found: list[ExtractedIOC] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            found.append(ExtractedIOC(value=value, kind=kind))

    for m in IPV4_RE.finditer(sample):
        ip = _normalize_ip(m.group(0))
        if ip:
            add("ip", ip)

    for m in IPV6_CANDIDATE.finditer(sample):
        ip = _normalize_ip(m.group(0))
        if ip and ":" in ip:
            add("ip", ip)

    for m in HASH_RE.finditer(sample):
        add("hash", m.group(0).lower())

    for m in DOMAIN_RE.finditer(sample):
        host = m.group(0).lower().rstrip(".")
        if IPV4_RE.fullmatch(host):
            continue
        add("domain", host)

    return found
