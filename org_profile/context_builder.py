"""Build LLM-ready organization context and IP policy matching."""

from __future__ import annotations

import html
import ipaddress
from typing import Any

from prompts.load import load_org_context_footer, load_vpn_guidance

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


def _network_from_authorized_vpn_line(
    line: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """First token is CIDR or single IP; name-only lines return None."""
    s = line.strip()
    if not s:
        return None
    first = s.split(None, 1)[0]
    try:
        return ipaddress.ip_network(first, strict=False)
    except ValueError:
        try:
            addr = ipaddress.ip_address(first)
            if addr.version == 4:
                return ipaddress.ip_network(f"{addr}/32", strict=False)
            return ipaddress.ip_network(f"{addr}/128", strict=False)
        except ValueError:
            return None


def ip_in_authorized_vpns(ip: str, profile: OrgProfile) -> str | None:
    """Return the matching authorized_vpns entry string, or None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for entry_line in profile.authorized_vpns:
        net = _network_from_authorized_vpn_line(entry_line)
        if net and addr in net:
            return entry_line
    return None


def _enrichment_suggests_vpn_or_proxy(entry: dict[str, Any]) -> bool:
    abuse = entry.get("abuseipdb") or {}
    if not isinstance(abuse, dict) or abuse.get("error"):
        return False
    usage = str(abuse.get("usageType", "") or "").lower()
    return any(kw in usage for kw in ("vpn", "proxy", "hosting"))


def apply_vpn_proxy_policy(entry: dict[str, Any], profile: OrgProfile | None) -> None:
    """
    For IPs flagged as VPN/proxy/hosting in enrichment, set entry['vpn_traffic']:
    authorized (CIDR matches authorized_vpns) or unknown (apply unknown_vpn_policy).
    """
    if entry.get("kind") != "ip" or entry.get("enrichment_skipped") or not profile:
        return
    if not _enrichment_suggests_vpn_or_proxy(entry):
        entry.pop("vpn_traffic", None)
        return
    ioc = entry.get("ioc")
    if not ioc or not isinstance(ioc, str):
        return
    matched = ip_in_authorized_vpns(ioc, profile)
    g = load_vpn_guidance()
    if matched:
        entry["vpn_traffic"] = {
            "status": "authorized",
            "matched_entry": matched,
            "guidance": g.get("authorized", ""),
        }
    else:
        entry["vpn_traffic"] = {
            "status": "unknown",
            "org_policy": profile.unknown_vpn_policy or "not set",
            "guidance": g.get("unknown", ""),
        }


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


async def build_org_context(chat_id: int) -> str:
    """Formatted block for LLM system user bundle (not the system prompt string itself)."""
    p = await load_profile(chat_id)
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
    if p.authorized_vpns:
        av = "; ".join(p.authorized_vpns)
        lines.append(f"- Authorized VPN/proxy ranges (org): {av}")
    else:
        lines.append("- Authorized VPN/proxy ranges (org): none recorded")
    lines.append(
        f"- Policy for unknown/unauthorized VPN or proxy traffic: "
        f"{p.unknown_vpn_policy or 'not set'} (block / monitor / allow)"
    )
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

    lines.append(load_org_context_footer())
    return "\n".join(lines)


def format_profile_summary(p: OrgProfile) -> str:
    lines = [
        f"<b>Organization</b>: {p.org_name or '—'}",
        f"<b>Industry</b>: {p.industry or '—'}",
        f"<b>Cloud</b>: {', '.join(p.cloud_providers) or '—'}",
        f"<b>Tor policy</b>: {p.tor_policy or '—'}",
        f"<b>Authorized VPNs</b>: {', '.join(p.authorized_vpns) or '—'}",
        f"<b>Unknown VPN/proxy policy</b>: {p.unknown_vpn_policy or '—'}",
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
