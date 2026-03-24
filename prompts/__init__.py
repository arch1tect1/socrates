"""Prompt assets for the LLM and dialogue layer."""

from .load import (
    load_followup_questions,
    load_org_context_footer,
    load_past_decisions_footer,
    load_system_prompt,
    load_vpn_guidance,
)

__all__ = [
    "load_followup_questions",
    "load_org_context_footer",
    "load_past_decisions_footer",
    "load_system_prompt",
    "load_vpn_guidance",
]
