"""Regex-based IOC extraction with defang, private-IP and domain whitelist filtering."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Optional

from ..models.alerts import ExtractedIOC, IOCType

# Default benign / infra domains to skip (override via DOMAIN_WHITELIST_CSV)
_DEFAULT_DOMAIN_WHITELIST = frozenset(
    {
        "microsoft.com",
        "google.com",
        "github.com",
        "googleapis.com",
        "gstatic.com",
        "apple.com",
        "cloudflare.com",
        "amazonaws.com",
        "windowsupdate.com",
        "live.com",
        "office.com",
    }
)


def _load_whitelist() -> frozenset[str]:
    raw = os.getenv("SOCrates_DOMAIN_WHITELIST", "")
    if not raw.strip():
        return _DEFAULT_DOMAIN_WHITELIST
    extra = {x.strip().lower().lstrip(".") for x in raw.split(",") if x.strip()}
    return _DEFAULT_DOMAIN_WHITELIST | extra


def refang(text: str) -> str:
    """Normalize defanged IOCs (same idea as main.refang)."""
    v = text.strip()
    v = v.replace("[.]", ".").replace("(dot)", ".").replace("[dot]", ".")
    v = re.sub(
        r"^hxxps?://",
        lambda m: m.group(0).replace("hxxp", "http"),
        v,
        flags=re.IGNORECASE,
    )
    v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
    v = v.replace("[://]", "://").replace("[:]", ":")
    v = v.replace("[at]", "@").replace("[@]", "@")
    return v


def _parse_ip(s: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _is_private_or_reserved_ip(s: str) -> bool:
    ip = _parse_ip(s)
    if ip is None:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )


def _is_whitelisted_domain(domain: str, whitelist: frozenset[str]) -> bool:
    d = domain.lower().rstrip(".")
    for w in whitelist:
        if d == w or d.endswith("." + w):
            return True
    return False


_RE_URL = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\.[a-zA-Z]{2,}\b"
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
# Simplified IPv6 (covers common forms)
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
    r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b",
    re.IGNORECASE,
)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


class IOCExtractor:
    def __init__(self, domain_whitelist: Optional[frozenset[str]] = None) -> None:
        self._whitelist = domain_whitelist if domain_whitelist is not None else _load_whitelist()

    def extract(self, text: str, context: Optional[str] = None) -> list[ExtractedIOC]:
        if not text or not text.strip():
            return []
        raw = refang(text)
        seen: set[tuple[str, str]] = set()
        out: list[ExtractedIOC] = []

        def add(ioc_type: IOCType, value: str, src: Optional[str] = None) -> None:
            value = value.strip()
            if not value:
                return
            key = (ioc_type, value.lower())
            if key in seen:
                return
            seen.add(key)
            out.append(
                ExtractedIOC(
                    ioc_type=ioc_type,
                    ioc_value=value,
                    extracted_from=context or src,
                )
            )

        # Order: URLs (first), emails, IPv4, IPv6, hashes, domains
        for m in _RE_URL.finditer(raw):
            u = m.group(0).rstrip(").,;]")
            if len(u) > 2048:
                continue
            add("url", u, "url_pattern")

        for m in _RE_EMAIL.finditer(raw):
            add("email", m.group(0).lower(), "email_pattern")

        for m in _RE_IPV4.finditer(raw):
            ip_s = m.group(0)
            if _parse_ip(ip_s) is None or _is_private_or_reserved_ip(ip_s):
                continue
            add("ip", ip_s, "ipv4_pattern")

        for m in _RE_IPV6.finditer(raw):
            ip_s = m.group(0)
            if _parse_ip(ip_s) is None or _is_private_or_reserved_ip(ip_s):
                continue
            add("ip", ip_s, "ipv6_pattern")

        for m in _RE_SHA256.finditer(raw):
            add("hash_sha256", m.group(0).lower(), "sha256_pattern")

        for m in _RE_SHA1.finditer(raw):
            add("hash_sha1", m.group(0).lower(), "sha1_pattern")

        for m in _RE_MD5.finditer(raw):
            add("hash_md5", m.group(0).lower(), "md5_pattern")

        url_values = [x.ioc_value for x in out if x.ioc_type == "url"]
        email_values = [x.ioc_value for x in out if x.ioc_type == "email"]

        for m in _RE_DOMAIN.finditer(raw):
            dom = m.group(0).lower()
            if any(dom in e for e in email_values):
                continue
            if any(dom in u for u in url_values):
                continue
            if _is_whitelisted_domain(dom, self._whitelist):
                continue
            add("domain", dom, "domain_pattern")

        return out

    def extract_from_dict(self, data: dict) -> list[ExtractedIOC]:
        chunks: list[str] = []

        def walk(obj: object) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    chunks.append(str(k))
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
            elif isinstance(obj, str):
                chunks.append(obj)
            elif obj is not None:
                chunks.append(str(obj))

        walk(data)
        blob = "\n".join(chunks)
        return self.extract(blob, context="json")
