"""Anthropic tool definitions for the L1 triage agent."""

from __future__ import annotations

# API shape matches Anthropic Messages `tools` parameter (`input_schema` = JSON Schema).
TRIAGE_TOOLS: list[dict] = [
    {
        "name": "check_virustotal",
        "description": (
            "Get VirusTotal reputation for IP, domain, URL, or file hash. "
            "Returns detection ratio, categories, recent detections."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_value": {"type": "string"},
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"],
                },
            },
            "required": ["ioc_value", "ioc_type"],
        },
    },
    {
        "name": "check_shodan",
        "description": (
            "Get Shodan data for an IP: open ports, services, banners, hostnames, ASN, country. "
            "Useful for understanding what kind of host it is."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "check_abuseipdb",
        "description": (
            "Check AbuseIPDB confidence score for an IP. "
            "Returns abuse confidence (0-100) and report categories."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "check_otx",
        "description": (
            "Check AlienVault OTX for threat intel pulses mentioning this IOC. "
            "Useful for attribution to threat actors or campaigns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_value": {"type": "string"},
                "ioc_type": {"type": "string"},
            },
            "required": ["ioc_value", "ioc_type"],
        },
    },
    {
        "name": "scan_url",
        "description": (
            "Submit URL to URLScan.io for active scanning. "
            "Returns screenshots, page behavior, IOCs observed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "get_whois",
        "description": (
            "Get WHOIS / RDAP data and domain registration timing for a domain. "
            "Domains registered recently (< 30 days) are often suspicious."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "search_similar_alerts",
        "description": (
            "Search past alerts for similar IOCs or rule patterns. "
            "Returns alerts with same IOCs or similar rule names in the last 30 days."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_value": {"type": "string"},
                "rule_pattern": {"type": "string"},
            },
        },
    },
]
