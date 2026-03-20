"""AI SOC Agent — Telegram bot entry point (python-telegram-bot v20+ async)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from telegram import Update
from telegram.constants import ChatAction
from telegram.error import TelegramError
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
from telegram.request import HTTPXRequest

from analyzer import analyze_enrichment
from config import load_config
from detector import InputKind, detect_input
from enrichers.abuseipdb import AbuseIPDBClient
from enrichers.shodan_client import ShodanClient
from enrichers.virustotal import VirusTotalClient
from formatter import format_telegram_report
from ioc_extractor import (
    extract_iocs_from_text,
    is_public_routable_ip,
    placeholder_ioc_note,
)

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("soc_copilot")

TELEGRAM_MAX_MESSAGE = 4096
SAFE_CHUNK = 3800


def _chunk_message(text: str, limit: int = SAFE_CHUNK) -> list[str]:
    if len(text) <= TELEGRAM_MAX_MESSAGE:
        return [text]
    parts: list[str] = []
    while text:
        parts.append(text[:limit])
        text = text[limit:]
    return parts


async def _typing_loop(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    """Best-effort typing indicator; network blips must not kill the handler."""
    try:
        while True:
            try:
                await context.bot.send_chat_action(
                    chat_id=chat_id, action=ChatAction.TYPING
                )
            except TelegramError as e:
                logger.warning("send_chat_action failed (ignored): %s", e)
            await asyncio.sleep(4.0)
    except asyncio.CancelledError:
        raise


@contextlib.asynccontextmanager
async def typing_heartbeat(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    task = asyncio.create_task(_typing_loop(context, chat_id))
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, TelegramError):
            await task


async def _enrich_one(
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    shodan: ShodanClient,
    kind: str,
    value: str,
) -> dict[str, Any]:
    if kind == "ip":
        vt_r, abuse_r, shodan_r = await asyncio.gather(
            vt.get_ip(value),
            abuse.check_ip(value),
            shodan.host(value),
        )
        return {
            "ioc": value,
            "kind": kind,
            "virustotal": vt_r,
            "abuseipdb": abuse_r,
            "shodan": shodan_r,
        }
    if kind == "domain":
        vt_r = await vt.get_domain(value)
        return {
            "ioc": value,
            "kind": kind,
            "virustotal": vt_r,
            "abuseipdb": None,
            "shodan": None,
        }
    if kind == "hash":
        vt_r = await vt.get_file(value)
        return {
            "ioc": value,
            "kind": kind,
            "virustotal": vt_r,
            "abuseipdb": None,
            "shodan": None,
        }
    raise ValueError(f"unsupported kind: {kind}")


async def build_payload(
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    shodan: ShodanClient,
    text: str,
) -> dict[str, Any]:
    det = detect_input(text)

    if det.kind == InputKind.RAW_LOG:
        iocs = extract_iocs_from_text(det.raw_text)
        entries: list[dict[str, Any]] = []
        extra_notes: list[str] = []
        pn = placeholder_ioc_note(det.raw_text)
        if pn:
            extra_notes.append(pn)

        for item in iocs:
            if item.kind == "ip" and not is_public_routable_ip(item.value):
                entries.append(
                    {
                        "ioc": item.value,
                        "kind": "ip",
                        "enrichment_skipped": True,
                        "reason": (
                            "Private/reserved IP — not sent to VirusTotal, AbuseIPDB, or "
                            "Shodan (those APIs apply to internet-routable indicators). "
                            "Use the public destination or external IOC from the log for TI."
                        ),
                    }
                )
                continue
            try:
                e = await _enrich_one(vt, abuse, shodan, item.kind, item.value)
                entries.append(e)
            except Exception as ex:  # noqa: BLE001
                logger.exception("enrichment failed for %s", item)
                entries.append(
                    {
                        "ioc": item.value,
                        "kind": item.kind,
                        "error": str(ex),
                    }
                )

        note = None
        if not entries:
            note = (
                "No IOCs were extracted from this message. "
                "Analyze the raw log/alert text and any embedded JSON only."
            )
            if extra_notes:
                note = f"{extra_notes[0]} {note}"
        elif not any(
            not e.get("enrichment_skipped") for e in entries
        ):
            note = (
                "No internet-routable IOCs were enriched (only private/internal IPs or "
                "non-extractable placeholders). "
                + (extra_notes[0] + " " if extra_notes else "")
                + "Paste a log line that includes a public dst IP/domain or a real file hash."
            )
        elif extra_notes:
            note = extra_notes[0]

        return {
            "input_mode": "raw_log",
            "original_text": det.raw_text,
            "ioc_entries": entries,
            "note": note,
        }

    assert det.primary_value is not None
    if det.kind == InputKind.IP and not is_public_routable_ip(det.primary_value):
        return {
            "input_mode": "single",
            "original_text": det.raw_text,
            "ioc_entries": [
                {
                    "ioc": det.primary_value,
                    "kind": "ip",
                    "enrichment_skipped": True,
                    "reason": (
                        "Private/reserved IP — not queried against VirusTotal, AbuseIPDB, "
                        "or Shodan."
                    ),
                }
            ],
            "note": (
                "Send a public/routable IP, a domain, or a file hash for external "
                "threat-intel enrichment."
            ),
        }

    entry = await _enrich_one(vt, abuse, shodan, det.kind.value, det.primary_value)
    return {
        "input_mode": "single",
        "original_text": det.raw_text,
        "ioc_entries": [entry],
        "note": None,
    }


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    text = (
        "<b>🛡 SOCrates</b> — your AI SOC teammate\n\n"
        "Send me any of these:\n"
        "- IP address → <code>185.220.101.34</code>\n"
        "- Domain → <code>suspicious-domain.com</code>\n"
        "- File hash (MD5/SHA1/SHA256)\n"
        "- Raw log or alert (JSON, syslog, any format)\n\n"
        "I'll enrich it via VirusTotal, AbuseIPDB &amp; Shodan, then give you a verdict, "
        "MITRE ATT&amp;CK mapping, and recommended actions.\n\n"
        "Just paste and send — no commands needed."
    )
    await update.effective_message.reply_html(text)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    text = (
        "<b>Supported inputs</b>\n"
        "• <b>IP</b> — standalone IPv4/IPv6 (enrichment: VT, AbuseIPDB, Shodan)\n"
        "• <b>Domain</b> — hostname-like string (VT)\n"
        "• <b>Hash</b> — 32 / 40 / 64 hex chars (VT file report)\n"
        "• <b>Anything else</b> — treated as raw log/alert; IOCs are regex-extracted "
        "and each is enriched.\n\n"
        "<b>Tips</b>\n"
        "• Paste single indicators alone for fastest classification.\n"
        "• For alerts, paste JSON or one log line; multiple IOCs are handled in order.\n"
        "• Free VirusTotal tier is rate-limited (4 lookups/min); bursts may queue.\n"
    )
    await update.effective_message.reply_html(text)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    if not msg or not msg.text:
        return
    chat_id = update.effective_chat.id
    user_text = msg.text.strip()
    if not user_text:
        return

    vt: VirusTotalClient = context.bot_data["vt"]
    abuse: AbuseIPDBClient = context.bot_data["abuse"]
    shodan: ShodanClient = context.bot_data["shodan"]

    async with typing_heartbeat(context, chat_id):
        try:
            payload = await build_payload(vt, abuse, shodan, user_text)
            analysis = await analyze_enrichment(payload)
        except Exception as e:  # noqa: BLE001
            logger.exception("pipeline error")
            await msg.reply_text(
                f"Processing failed: {e}\n\nCheck logs and API keys, then try again."
            )
            return

    formatted = format_telegram_report(analysis)
    for chunk in _chunk_message(formatted):
        try:
            await msg.reply_html(chunk)
        except TelegramError as e:
            logger.warning("reply_html failed, falling back to plain text: %s", e)
            await msg.reply_text(chunk[:TELEGRAM_MAX_MESSAGE])


def main() -> None:
    cfg = load_config()
    vt = VirusTotalClient(cfg.virustotal_api_key, timeout=cfg.http_timeout_seconds)
    abuse = AbuseIPDBClient(cfg.abuseipdb_api_key, timeout=cfg.http_timeout_seconds)
    shodan = ShodanClient(cfg.shodan_api_key, timeout=cfg.http_timeout_seconds)

    request = HTTPXRequest(
        connect_timeout=45.0,
        read_timeout=45.0,
        write_timeout=45.0,
        pool_timeout=10.0,
    )
    app = Application.builder().token(cfg.telegram_bot_token).request(request).build()

    app.bot_data["config"] = cfg
    app.bot_data["vt"] = vt
    app.bot_data["abuse"] = abuse
    app.bot_data["shodan"] = shodan

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    logger.info("AI SOC Agent starting (polling)")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
