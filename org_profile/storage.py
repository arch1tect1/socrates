"""PostgreSQL storage for organization profiles (async)."""

from __future__ import annotations

import re

from sqlalchemy import select

from database.crud import get_or_create_user
from database.engine import get_async_session
from database.models import OrgProfileDB, UserDB

from .models import OrgProfile


async def load_profile(telegram_user_id: int) -> OrgProfile | None:
    async with get_async_session() as session:
        result = await session.execute(
            select(OrgProfileDB)
            .join(UserDB)
            .where(UserDB.telegram_user_id == telegram_user_id)
        )
        row = result.scalar_one_or_none()
        if not row:
            return None
        return OrgProfile(
            chat_id=telegram_user_id,
            industry=row.industry or "",
            org_name=row.org_name or "",
            cloud_providers=row.cloud_providers or [],
            tor_policy=row.tor_policy or "",
            authorized_vpns=row.authorized_vpns or [],
            unknown_vpn_policy=row.unknown_vpn_policy or "",
            never_block_ips=row.never_block_ips or [],
            own_infrastructure=row.own_infrastructure or [],
            security_stack=row.security_stack or "",
            custom_policies=row.custom_policies or [],
            updated_at=row.updated_at.isoformat() if row.updated_at else "",
        )


async def save_profile(profile: OrgProfile) -> None:
    telegram_user_id = profile.chat_id
    user_id = await get_or_create_user(telegram_user_id)

    async with get_async_session() as session:
        result = await session.execute(
            select(OrgProfileDB).where(OrgProfileDB.user_id == user_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.industry = profile.industry
            existing.org_name = profile.org_name
            existing.cloud_providers = profile.cloud_providers
            existing.tor_policy = profile.tor_policy
            existing.authorized_vpns = profile.authorized_vpns
            existing.unknown_vpn_policy = profile.unknown_vpn_policy
            existing.never_block_ips = profile.never_block_ips
            existing.own_infrastructure = profile.own_infrastructure
            existing.security_stack = profile.security_stack
            existing.custom_policies = profile.custom_policies
        else:
            new_profile = OrgProfileDB(
                user_id=user_id,
                industry=profile.industry,
                org_name=profile.org_name,
                cloud_providers=profile.cloud_providers,
                tor_policy=profile.tor_policy,
                authorized_vpns=profile.authorized_vpns,
                unknown_vpn_policy=profile.unknown_vpn_policy,
                never_block_ips=profile.never_block_ips,
                own_infrastructure=profile.own_infrastructure,
                security_stack=profile.security_stack,
                custom_policies=profile.custom_policies,
            )
            session.add(new_profile)

        await session.commit()


# ---------------------------------------------------------------------------
# Utility parsers (unchanged from JSON-era code)
# ---------------------------------------------------------------------------

def parse_cidr_list(text: str) -> list[str]:
    """Parse comma-separated CIDRs; 'skip' or empty → []."""
    t = text.strip().lower()
    if not t or t == "skip":
        return []
    parts = re.split(r"[,\n;]+", text)
    out: list[str] = []
    for p in parts:
        s = p.strip()
        if s:
            out.append(s)
    return out


def parse_cloud_list(text: str) -> list[str]:
    t = text.strip().lower()
    if not t or t == "skip":
        return []
    if t == "none":
        return []
    parts = re.split(r"[,\n;]+", text)
    return [p.strip() for p in parts if p.strip()]
