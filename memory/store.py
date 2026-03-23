"""JSON storage for analyst decisions."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import DecisionRecord


def decisions_dir(data_dir: Path, chat_id: int) -> Path:
    return data_dir / "decisions" / str(chat_id)


def save_decision(data_dir: Path, record: DecisionRecord) -> Path:
    d = decisions_dir(data_dir, record.chat_id)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{record.id}.json"
    path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
    return path


def load_decision(data_dir: Path, chat_id: int, decision_id: str) -> DecisionRecord | None:
    path = decisions_dir(data_dir, chat_id) / f"{decision_id}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return DecisionRecord.from_dict(data)
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        return None


def load_all_decisions(data_dir: Path, chat_id: int) -> list[DecisionRecord]:
    base = decisions_dir(data_dir, chat_id)
    if not base.is_dir():
        return []
    out: list[DecisionRecord] = []
    for path in sorted(base.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            out.append(DecisionRecord.from_dict(data))
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            continue
    return out


def parse_verdict_lines(llm_text: str) -> tuple[str, str]:
    verdict = ""
    severity = ""
    for line in llm_text.splitlines():
        u = line.upper()
        if "VERDICT:" in u and not verdict:
            m = re.search(r"VERDICT:\s*\[?([^\]\n]+)\]?", line, re.I)
            if m:
                verdict = m.group(1).strip()
        if "SEVERITY:" in u and not severity:
            m = re.search(r"SEVERITY:\s*\[?([^\]\n]+)\]?", line, re.I)
            if m:
                severity = m.group(1).strip()
    return verdict, severity


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clear_all_decisions(data_dir: Path, chat_id: int) -> int:
    base = decisions_dir(data_dir, chat_id)
    if not base.is_dir():
        return 0
    n = 0
    for path in base.glob("*.json"):
        path.unlink(missing_ok=True)
        n += 1
    return n
