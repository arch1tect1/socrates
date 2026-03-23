"""Build LLM-ready organization context and IP policy matching."""

from __future__ import annotations

import html
import ipaddress
from pathlib import Path
from typing import Any

from .models import OrgProfile
from .storage import load_profile

_INDUSTRY_NOTES: dict[str, str] = {
    "finance": "highly regulated, strict compliance requirements",
    "healthcare": "HIPAA-sensitive environment",
    "education": "large user base, academic network considerations",
    "government": "strict policy and classification context",
    "tech": "typical SaaS/IT environment",
    "ecommerce": "customer-facing uptime critical",
    "other": "general enterprise",
}


def classify_ip_against_org(ip: str, profile: OrgProfile) -> str | None:
    """
    Return NEVER_BLOCK, OWN_INFRA, or None if no CIDR match.
    Never-block is checked first.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for cidr_str in profile.never_block_ips:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if addr in net:
                return "NEVER_BLOCK"
        except ValueError:
            continue

    for cidr_str in profile.own_infrastructure:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if addr in net:
                return "OWN_INFRA"
        except ValueError:
            continue

    return None


def apply_org_match_to_entry(entry: dict[str, Any], profile: OrgProfile | None) -> None:
    """Mutate entry in place with org_match when kind is ip."""
    if entry.get("kind") != "ip" or entry.get("enrichment_skipped"):
        return
    if not profile:
        return
    ioc = entry.get("ioc")
    if not ioc or not isinstance(ioc, str):
        return
    m = classify_ip_against_org(ioc, profile)
    if m:
        entry["org_match"] = m


def build_org_context(data_dir: Path, chat_id: int) -> str:
    """Formatted block for LLM system user bundle (not the system prompt string itself)."""
    p = load_profile(data_dir, chat_id)
    if not p or not (p.org_name or p.industry):
        return ""

    ind = p.industry.lower() if p.industry else "unknown"
    ind_note = _INDUSTRY_NOTES.get(ind, "general enterprise")

    lines = [
        "ORGANIZATION CONTEXT:",
        f"- Industry: {p.industry or 'unknown'} ({ind_note})",
    ]
    if p.org_name:
        lines.append(f"- Organization name: {p.org_name}")
    if p.cloud_providers:
        cp = ", ".join(p.cloud_providers)
        lines.append(
            f"- Cloud providers: {cp} (their IP ranges may appear in alerts — "
            "do NOT recommend blocking without further context)"
        )
    lines.append(f"- Tor policy: {p.tor_policy or 'not set'}")
    lines.append(f"- VPN policy (external VPNs): {p.vpn_policy or 'not set'}")
    if p.never_block_ips:
        lines.append(f"- Never-block CIDRs: {', '.join(p.never_block_ips)}")
    if p.own_infrastructure:
        lines.append(f"- Own infrastructure CIDRs: {', '.join(p.own_infrastructure)}")
    if p.security_stack:
        lines.append(f"- Security stack: {p.security_stack}")
    if p.custom_policies:
        lines.append("- Custom policies:")
        for rule in p.custom_policies:
            lines.append(f"  • {rule}")

    lines.append(
        "IMPORTANT: Your recommendations MUST respect these organization policies. "
        "If an IOC conflicts with a never-block IP or belongs to the organization's "
        "cloud provider context, you MUST flag this explicitly and suggest alternatives "
        "to full blocking (rate limiting, geo-blocking, monitoring, WAF rules, etc.)."
    )
    return "\n".join(lines)


def format_profile_summary(p: OrgProfile) -> str:
    lines = [
        f"<b>Organization</b>: {p.org_name or '—'}",
        f"<b>Industry</b>: {p.industry or '—'}",
        f"<b>Cloud</b>: {', '.join(p.cloud_providers) or '—'}",
        f"<b>Tor policy</b>: {p.tor_policy or '—'}",
        f"<b>VPN policy</b>: {p.vpn_policy or '—'}",
        f"<b>Never-block CIDRs</b>: {', '.join(p.never_block_ips) or '—'}",
        f"<b>Own infra CIDRs</b>: {', '.join(p.own_infrastructure) or '—'}",
        f"<b>Security stack</b>: {p.security_stack or '—'}",
    ]
    if p.custom_policies:
        lines.append("<b>Custom policies</b>:")
        for r in p.custom_policies:
            lines.append(f"  • {html.escape(r)}")
    lines.append(f"<i>Updated: {p.updated_at or '—'}</i>")
    return "\n".join(lines)
