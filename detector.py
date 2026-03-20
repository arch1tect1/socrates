"""IOC type detection using regex and ipaddress validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class InputKind(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    RAW_LOG = "raw_log"


@dataclass(frozen=True)
class DetectionResult:
    kind: InputKind
    """Single-IOC mode: the primary value. For raw_log, may be empty."""
    primary_value: str | None
    """Original user text (trimmed)."""
    raw_text: str


# IPv4
_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Compressed / full IPv6 (common forms); validate with ipaddress after match
_IPV6_LOOSE = re.compile(
    r"^[0-9a-fA-F:.]+$"
)

# MD5 / SHA1 / SHA256 — full string only
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

# Domain-like hostname (not an IP); labels with TLD
_DOMAIN = re.compile(
    r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def _is_plausible_ipv6(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return ":" in s
    except ValueError:
        return False


def detect_input(text: str) -> DetectionResult:
    """Classify user message: standalone IP, hash, domain, or raw log / alert."""
    raw = text.strip()
    if not raw:
        return DetectionResult(InputKind.RAW_LOG, None, raw)

    if _IPV4.match(raw):
        return DetectionResult(InputKind.IP, raw, raw)

    if _IPV6_LOOSE.match(raw) and _is_plausible_ipv6(raw):
        return DetectionResult(InputKind.IP, raw, raw)

    if _HASH.match(raw):
        return DetectionResult(InputKind.HASH, raw.lower(), raw)

    if _DOMAIN.match(raw):
        return DetectionResult(InputKind.DOMAIN, raw.lower(), raw)

    return DetectionResult(InputKind.RAW_LOG, None, raw)
