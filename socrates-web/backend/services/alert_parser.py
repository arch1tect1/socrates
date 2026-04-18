"""Alert format parsers (Wazuh JSON, manual paste)."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Optional

from ..models.alerts import AlertCreate, Severity


def _wazuh_level_to_severity(level: int) -> Severity:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


class AlertParser(ABC):
    @abstractmethod
    def can_parse(self, payload: dict[str, Any]) -> bool:
        ...

    @abstractmethod
    def parse(self, payload: dict[str, Any]) -> AlertCreate:
        ...


class WazuhParser(AlertParser):
    def can_parse(self, payload: dict[str, Any]) -> bool:
        rule = payload.get("rule")
        if not isinstance(rule, dict):
            return False
        if "level" not in rule:
            return False
        return "agent" in payload

    def parse(self, payload: dict[str, Any]) -> AlertCreate:
        rule = payload.get("rule") or {}
        agent = payload.get("agent") or {}
        level = int(rule.get("level", 0))
        severity = _wazuh_level_to_severity(level)
        rule_id = str(rule.get("id", "")) if rule.get("id") is not None else None
        title = (rule.get("description") or "Wazuh alert").strip() or "Wazuh alert"
        parts: list[str] = []
        if payload.get("full_log"):
            parts.append(str(payload["full_log"]))
        data = payload.get("data")
        if isinstance(data, dict):
            parts.append(json.dumps(data, ensure_ascii=False))
        description = "\n".join(parts) if parts else None
        agent_name = agent.get("name") or "unknown"
        source = f"wazuh:{agent_name}"

        return AlertCreate(
            source=source,
            source_alert_id=rule_id,
            rule_name=title,
            severity=severity,
            title=title,
            description=description,
            raw_payload=dict(payload),
        )


class ManualInputParser(AlertParser):
    """Paste raw log / email body — expects `raw_text` plus optional metadata."""

    def can_parse(self, payload: dict[str, Any]) -> bool:
        if payload.get("_force_manual") and str(payload.get("raw_text", "")).strip():
            return True
        return (
            "raw_text" in payload
            and isinstance(payload.get("raw_text"), str)
            and "rule" not in payload
        )

    def parse(self, payload: dict[str, Any]) -> AlertCreate:
        raw = str(payload.get("raw_text", "")).strip()
        if not raw:
            raise ValueError("manual payload requires non-empty raw_text")
        source = str(payload.get("source", payload.get("source_label", "manual")))[:256]
        title = (payload.get("title") or "Manual submission").strip() or "Manual submission"
        severity: Severity = payload.get("severity") or "medium"
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        desc = payload.get("description")
        return AlertCreate(
            source=source,
            source_alert_id=payload.get("source_alert_id"),
            rule_name=payload.get("rule_name"),
            severity=severity,
            title=title,
            description=str(desc) if desc is not None else raw[:5000],
            raw_payload=dict(payload),
        )


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: list[AlertParser] = [
            WazuhParser(),
            ManualInputParser(),
        ]

    def register(self, parser: AlertParser, first: bool = False) -> None:
        if first:
            self._parsers.insert(0, parser)
        else:
            self._parsers.append(parser)

    def parse(
        self,
        payload: dict[str, Any],
        *,
        parser_hint: Optional[str] = None,
    ) -> AlertCreate:
        hint = (parser_hint or "").strip().lower()
        ordered = list(self._parsers)
        if hint == "wazuh":
            ordered = [WazuhParser(), ManualInputParser()]
        elif hint == "manual":
            ordered = [ManualInputParser(), WazuhParser()]

        last_err: Optional[Exception] = None
        for p in ordered:
            try:
                if p.can_parse(payload):
                    return p.parse(payload)
            except Exception as e:
                last_err = e
                continue

        if last_err:
            raise ValueError(f"No parser matched payload: {last_err}") from last_err
        raise ValueError(
            "No parser could interpret this payload. "
            "Send Wazuh-shaped JSON or {raw_text, source?, title?, severity?} for manual ingest."
        )
