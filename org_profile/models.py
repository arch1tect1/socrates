"""Organization profile data model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class OrgProfile:
    chat_id: int
    org_name: str = ""
    industry: str = ""
    cloud_providers: list[str] = field(default_factory=list)
    tor_policy: str = ""
    vpn_policy: str = ""
    never_block_ips: list[str] = field(default_factory=list)
    own_infrastructure: list[str] = field(default_factory=list)
    security_stack: str = ""
    custom_policies: list[str] = field(default_factory=list)
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgProfile:
        return cls(
            chat_id=int(data.get("chat_id", 0)),
            org_name=str(data.get("org_name", "")),
            industry=str(data.get("industry", "")),
            cloud_providers=list(data.get("cloud_providers") or []),
            tor_policy=str(data.get("tor_policy", "")),
            vpn_policy=str(data.get("vpn_policy", "")),
            never_block_ips=list(data.get("never_block_ips") or []),
            own_infrastructure=list(data.get("own_infrastructure") or []),
            security_stack=str(data.get("security_stack", "")),
            custom_policies=list(data.get("custom_policies") or []),
            updated_at=str(data.get("updated_at", "")),
        )

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
