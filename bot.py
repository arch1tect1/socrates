"""SOCrates — Telegram bot entry point (python-telegram-bot v20+ async)."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import uuid
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, Update
from telegram.constants import ChatAction
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    TypeHandler,
    filters,
)
from telegram.request import HTTPXRequest

from analyzer import analyze_enrichment
from config import load_config
from database import close_db, get_admin_stats, get_or_create_user, init_db
from detector import InputKind, detect_input
from dialogue.ambiguity import detect_ambiguity, first_enriched_entry
from dialogue.followup import format_preliminary, generate_followups
from dialogue.session import SessionState, clear_session, get_session, put_session
from enrichers.abuseipdb import AbuseIPDBClient
from enrichers.otx import OTXClient
from enrichers.shodan_client import ShodanClient
from enrichers.urlscan import UrlscanClient
from enrichers.virustotal import VirusTotalClient
from formatter import format_telegram_report
from ioc_extractor import (
    extract_iocs_from_text,
    is_public_routable_ip,
    placeholder_ioc_note,
)
from memory.feedback import create_decision_record, update_feedback
from memory.models import DecisionRecord
from memory.retriever import (
    build_enrichment_summary,
    find_similar_decisions,
    format_past_decisions_for_llm,
)
from memory.store import clear_all_decisions, load_all_decisions, parse_verdict_lines, save_decision
from metrics import (
    analyses_total,
    feedback_total,
    start_metrics_server,
    verdicts_total,
)
from org_profile.context_builder import (
    apply_org_match_to_entry,
    apply_vpn_proxy_policy,
    build_org_context,
    format_profile_summary,
)
from org_profile.models import OrgProfile
from org_profile.storage import load_profile, parse_cidr_list, parse_cloud_list, save_profile

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
    urlscan: UrlscanClient,
    otx: OTXClient,
    kind: str,
    value: str,
) -> dict[str, Any]:
    if kind == "ip":
        results = await asyncio.gather(
            vt.get_ip(value),
            abuse.check_ip(value),
            shodan.host(value),
            otx.get_ip(value),
            return_exceptions=True,
        )
        vt_r, abuse_r, shodan_r, otx_r = [
            r if not isinstance(r, Exception) else {"error": True, "detail": str(r)}
            for r in results
        ]
        return {
            "ioc": value,
            "kind": kind,
            "virustotal": vt_r,
            "abuseipdb": abuse_r,
            "shodan": shodan_r,
            "urlscan": None,
            "otx": otx_r,
        }
    if kind == "domain":
        results = await asyncio.gather(
            vt.get_domain(value),
            urlscan.search_domain(value),
            otx.get_domain(value),
            return_exceptions=True,
        )
        vt_r, urlscan_r, otx_r = [
            r if not isinstance(r, Exception) else {"error": True, "detail": str(r)}
            for r in results
        ]
        return {
            "ioc": value,
            "kind": kind,
            "virustotal": vt_r,
            "abuseipdb": None,
            "shodan": None,
            "urlscan": urlscan_r,
            "otx": otx_r,
        }
    if kind == "hash":
        results = await asyncio.gather(
            vt.get_file(value),
            otx.get_file(value),
            return_exceptions=True,
        )
        vt_r, otx_r = [
            r if not isinstance(r, Exception) else {"error": True, "detail": str(r)}
            for r in results
        ]
        return {
            "ioc": value,
            "kind": kind,
            "virustotal": vt_r,
            "abuseipdb": None,
            "shodan": None,
            "urlscan": None,
            "otx": otx_r,
        }
    raise ValueError(f"unsupported kind: {kind}")


async def build_payload(
    vt: VirusTotalClient,
    abuse: AbuseIPDBClient,
    shodan: ShodanClient,
    urlscan: UrlscanClient,
    otx: OTXClient,
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
                e = await _enrich_one(
                    vt, abuse, shodan, urlscan, otx, item.kind, item.value
                )
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
        elif not any(not e.get("enrichment_skipped") for e in entries):
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

    entry = await _enrich_one(
        vt, abuse, shodan, urlscan, otx, det.kind.value, det.primary_value
    )
    return {
        "input_mode": "single",
        "original_text": det.raw_text,
        "ioc_entries": [entry],
        "note": None,
    }


async def _apply_org_profile_to_payload(
    payload: dict[str, Any], chat_id: int
) -> OrgProfile | None:
    prof = await load_profile(chat_id)
    if not prof:
        return None
    for e in payload.get("ioc_entries") or []:
        apply_org_match_to_entry(e, prof)
        apply_vpn_proxy_policy(e, prof)
    return prof


def _should_show_feedback_buttons(
    entry: dict[str, Any] | None,
    payload: dict[str, Any],
    verdict: str,
    analysis: str,
) -> bool:
    if entry is None:
        return False
    note = (payload.get("note") or "").lower()
    if "no iocs were extracted" in note:
        return False
    v = (verdict or "").strip().lower()
    if v == "inconclusive":
        a = analysis.lower()
        if "no iocs extracted" in a or "no ioc extracted" in a:
            return False
    return True


def _feedback_keyboard(decision_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("✅ Agree", callback_data=f"f:agree:{decision_id}"),
                InlineKeyboardButton("❌ Disagree", callback_data=f"f:disagree:{decision_id}"),
                InlineKeyboardButton("🔶 Partial", callback_data=f"f:partial:{decision_id}"),
            ],
            [
                InlineKeyboardButton("🗒 Add note", callback_data=f"f:note:{decision_id}"),
            ],
        ]
    )


async def _send_verdict_with_memory(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    analysis: str,
    *,
    llm_source: str = "",
    entry: dict[str, Any] | None,
    payload: dict[str, Any],
    ambiguity_flags: list[str],
    chat_id: int,
) -> None:
    msg = update.effective_message
    if not msg:
        return
    decision_id = uuid.uuid4().hex
    v, sev = parse_verdict_lines(analysis)
    show_feedback = _should_show_feedback_buttons(entry, payload, v, analysis)
    summ = build_enrichment_summary(entry) if entry else {}
    rec = create_decision_record(
        decision_id=decision_id,
        chat_id=chat_id,
        ioc_type=entry.get("kind", "") if entry else "",
        ioc_value=entry.get("ioc", "") if entry else "",
        enrichment_summary=summ,
        ambiguity_flags=ambiguity_flags,
        llm_response=analysis,
        ai_verdict=v,
        ai_severity=sev,
    )
    await save_decision(rec)

    # Prometheus metrics
    analyses_total.labels(ioc_type=rec.ioc_type or "unknown").inc()
    if v:
        verdicts_total.labels(verdict=v.lower()).inc()

    src_line = f"LLM: {llm_source}" if llm_source else ""
    formatted = format_telegram_report(
        analysis, title="SOCrates", llm_source=src_line or None
    )
    chunks = _chunk_message(formatted)
    for i, chunk in enumerate(chunks):
        rm = (
            _feedback_keyboard(decision_id)
            if i == len(chunks) - 1 and show_feedback
            else None
        )
        try:
            await msg.reply_html(chunk, reply_markup=rm)
        except TelegramError as e:
            logger.warning("reply_html failed: %s", e)
            await msg.reply_text(chunk[:TELEGRAM_MAX_MESSAGE])


async def _run_llm_pipeline(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    payload: dict[str, Any],
    *,
    entry: dict[str, Any] | None,
    chat_id: int,
    org_block: str,
    past_block: str,
    followup_block: str = "",
    ambiguity_flags: list[str] | None = None,
) -> None:
    msg = update.effective_message
    ambiguity_flags = ambiguity_flags or []
    async with typing_heartbeat(context, chat_id):
        try:
            analysis, llm_source = await analyze_enrichment(
                payload,
                org_context_block=org_block,
                past_decisions_block=past_block,
                analyst_followup_block=followup_block,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("pipeline error")
            if msg:
                await msg.reply_text(
                    f"Processing failed: {e}\n\nCheck logs and API keys, then try again."
                )
            return
    await _send_verdict_with_memory(
        update,
        context,
        analysis,
        llm_source=llm_source,
        entry=entry,
        payload=payload,
        ambiguity_flags=ambiguity_flags,
        chat_id=chat_id,
    )


async def process_ioc_pipeline(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_text: str,
) -> None:
    msg = update.effective_message
    chat_id = update.effective_chat.id
    vt: VirusTotalClient = context.bot_data["vt"]
    abuse: AbuseIPDBClient = context.bot_data["abuse"]
    shodan: ShodanClient = context.bot_data["shodan"]
    urlscan: UrlscanClient = context.bot_data["urlscan"]
    otx: OTXClient = context.bot_data["otx"]

    payload = await build_payload(vt, abuse, shodan, urlscan, otx, user_text)
    prof = await _apply_org_profile_to_payload(payload, chat_id)
    org_block = await build_org_context(chat_id)

    entry = first_enriched_entry(payload)
    past_block = ""
    if entry:
        sim = await find_similar_decisions(
            chat_id,
            entry.get("kind", ""),
            str(entry.get("ioc", "")),
            entry,
            limit=3,
        )
        past_block = format_past_decisions_for_llm(sim)

    prof_dict = prof.to_dict() if prof else None
    flags: list[str] = []
    if entry:
        flags = detect_ambiguity(entry, prof_dict)

    multi = len(payload.get("ioc_entries") or []) > 1
    use_dialogue = bool(flags) and entry and not multi

    if use_dialogue:
        questions = generate_followups(flags, entry)
        prelim = format_preliminary(entry, flags)
        sess = SessionState(
            chat_id=chat_id,
            original_input=user_text,
            ioc_type=entry.get("kind", ""),
            ioc_value=str(entry.get("ioc", "")),
            enrichment_data=entry,
            payload=payload,
            org_profile_dict=prof_dict,
            ambiguity_flags=flags,
            followup_questions=questions,
            status="awaiting_followup",
        )
        await put_session(sess)
        qtext = "\n".join(f"• {q}" for q in questions)
        total_q = len(questions)
        first_q = questions[0] if questions else "Please share any relevant context."
        if msg:
            await msg.reply_html(
                f"{prelim}\n\n"
                f"❓ <b>More context needed</b> before a final verdict:\n\n{qtext}\n\n"
                f"Please answer them one by one. Start with question 1/{total_q}:\n"
                f"{first_q}\n\n"
                f"Send /skip any time for a best-effort verdict.",
            )
        return

    await _run_llm_pipeline(
        update,
        context,
        payload,
        entry=entry,
        chat_id=chat_id,
        org_block=org_block,
        past_block=past_block,
        ambiguity_flags=flags,
    )


# ---------------------------------------------------------------------------
# User tracking middleware
# ---------------------------------------------------------------------------

async def track_user_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Runs in handler group -1 for every update to track / register users."""
    user = update.effective_user
    if user:
        await get_or_create_user(
            telegram_user_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            language_code=user.language_code,
        )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    text = (
        "🛡 SOCrates — your AI SOC teammate\n\n"
        "Send me any IP, domain, file hash, or raw log/alert — I'll enrich it and give you "
        "a threat verdict with MITRE ATT&amp;CK mapping and recommended actions.\n\n"
        "⚙️ <b>FIRST TIME?</b> Set up your organization profile for smarter, context-aware "
        "verdicts:\n"
        "→ <code>/setup</code> — Configure your org policies, cloud providers, and protected "
        "assets (recommended for teams)\n\n"
        "Skip <code>/setup</code> if you're using SOCrates for personal research — I'll still "
        "analyze IOCs, just without org-specific recommendations.\n\n"
        "📌 <b>COMMANDS:</b>\n"
        "/setup — Set up organization profile\n"
        "/profile — View your current profile\n"
        "/addpolicy — Add a custom security policy\n"
        "/help — Show supported input types and examples\n"
        "/history — View past analyses\n"
        "/stats — View analysis statistics\n\n"
        "Just paste any IOC and send — no commands needed."
    )
    await update.effective_message.reply_html(text)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    text = (
        "<b>Inputs</b>\n"
        "• IP / domain / hash / raw log — auto-detected\n\n"
        "<b>Organization</b>\n"
        "/setup — guided org profile\n"
        "/profile — show profile\n"
        "/addpolicy &lt;text&gt; — add custom policy\n"
        "/clearpolicy — remove custom policies\n\n"
        "<b>Analysis</b>\n"
        "/skip — during follow-up questions, force best-effort verdict\n\n"
        "<b>Memory</b>\n"
        "/history [ioc] — past decisions\n"
        "/stats — feedback stats\n"
        "/export — CSV export\n"
        "/clearhistory yes — delete all stored decisions\n"
    )
    await update.effective_message.reply_html(text)


async def cmd_setup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    owner_user_id = int(update.effective_user.id) if update.effective_user else None
    _setup_clear_state(context, chat_id)
    _setup_clear_user_sessions(context, owner_user_id, keep_chat_id=chat_id)
    new_state = {
        "origin_chat_id": int(chat_id),
        "owner_user_id": owner_user_id,
        "step": 0,
        "answers": {},
        "pending_custom": None,
        "awaiting_custom_input": False,
        "multi_selected": [],
        "status": "in_progress",
        "editing_field": None,
        "last_prompt_signature": None,
    }
    _setup_save_state(context, chat_id, new_state)
    await _send_setup_question(update.effective_message, context, chat_id)


async def cmd_profile(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    uid = update.effective_user.id if update.effective_user else chat_id
    p = await load_profile(uid)
    if p is None and uid != chat_id:
        p = await load_profile(chat_id)
    if not p:
        await update.effective_message.reply_text("No profile yet. Use /setup.")
        return
    await update.effective_message.reply_html(format_profile_summary(p))


async def cmd_addpolicy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    text = " ".join(context.args) if context.args else ""
    if not text.strip():
        await update.effective_message.reply_text(
            "Usage: /addpolicy Amazon and Google Cloud IPs should never be fully blocked"
        )
        return
    chat_id = update.effective_chat.id
    p = await load_profile(chat_id)
    if not p:
        await update.effective_message.reply_text("Run /setup first.")
        return
    p.custom_policies.append(text.strip())
    await save_profile(p)
    await update.effective_message.reply_text("Policy added.")


async def cmd_clearpolicy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    p = await load_profile(chat_id)
    if not p:
        await update.effective_message.reply_text("No profile.")
        return
    p.custom_policies = []
    await save_profile(p)
    await update.effective_message.reply_text("Custom policies cleared.")


async def cmd_skip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    sess = await get_session(chat_id)
    if not sess or sess.status != "awaiting_followup":
        await update.effective_message.reply_text(
            "No active analysis to skip. Send me an IOC or alert to analyze."
        )
        return
    org_block = await build_org_context(chat_id)
    entry = sess.enrichment_data
    past_block = ""
    if entry:
        sim = await find_similar_decisions(
            chat_id,
            entry.get("kind", ""),
            str(entry.get("ioc", "")),
            entry,
        )
        past_block = format_past_decisions_for_llm(sim)
    follow = (
        "ANALYST PROVIDED ADDITIONAL CONTEXT:\n"
        "Analyst chose /skip — provide a best-effort verdict without follow-up answers."
    )
    await clear_session(chat_id)
    await _run_llm_pipeline(
        update,
        context,
        sess.payload,
        entry=entry,
        chat_id=chat_id,
        org_block=org_block,
        past_block=past_block,
        followup_block=follow,
        ambiguity_flags=sess.ambiguity_flags,
    )


async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    ioc_filter = " ".join(context.args) if context.args else None
    all_d = await load_all_decisions(chat_id)
    if ioc_filter:
        all_d = [d for d in all_d if ioc_filter in d.ioc_value]
    lines = []
    for d in all_d[:10]:
        lines.append(
            f"• {d.timestamp[:16]} | {d.ioc_type} <code>{d.ioc_value}</code> | "
            f"{d.ai_verdict or '?'} | feedback: {d.analyst_feedback or '—'}"
        )
    if not lines:
        await update.effective_message.reply_text("No decisions stored yet.")
        return
    await update.effective_message.reply_html(
        "<b>Last decisions</b>\n" + "\n".join(lines)
    )


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    all_d = await load_all_decisions(chat_id)
    n = len(all_d)
    agree = sum(1 for d in all_d if d.analyst_feedback == "agree")
    disagree = sum(1 for d in all_d if d.analyst_feedback == "disagree")
    partial = sum(1 for d in all_d if d.analyst_feedback == "partial")
    await update.effective_message.reply_text(
        f"Total decisions: {n}\n"
        f"Agree: {agree} | Disagree: {disagree} | Partial: {partial}\n"
        f"(Feedback only if you used buttons after a verdict.)"
    )


async def cmd_export(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    chat_id = update.effective_chat.id
    all_d = await load_all_decisions(chat_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "timestamp",
            "ioc_type",
            "ioc_value",
            "verdict",
            "severity",
            "feedback",
            "note",
        ]
    )
    for d in all_d:
        w.writerow(
            [
                d.id,
                d.timestamp,
                d.ioc_type,
                d.ioc_value,
                d.ai_verdict,
                d.ai_severity,
                d.analyst_feedback,
                d.analyst_note,
            ]
        )
    raw = buf.getvalue().encode("utf-8")
    bio = io.BytesIO(raw)
    await update.effective_message.reply_document(
        document=InputFile(bio, filename="socrates_decisions.csv"),
        caption="SOCrates decision export",
    )


async def cmd_clearhistory(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message:
        return
    if not context.args or context.args[0].lower() != "yes":
        await update.effective_message.reply_text(
            "This deletes all stored decisions for this chat. Send: /clearhistory yes"
        )
        return
    chat_id = update.effective_chat.id
    n = await clear_all_decisions(chat_id)
    await update.effective_message.reply_text(f"Cleared {n} decision(s).")


# ---------------------------------------------------------------------------
# /admin — protected analytics command
# ---------------------------------------------------------------------------

async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_message or not update.effective_user:
        return
    admin_id = context.bot_data["config"].admin_telegram_id
    if update.effective_user.id != admin_id:
        await update.effective_message.reply_text("⛔ Access denied.")
        return

    stats = await get_admin_stats()

    ioc_lines = "\n".join(
        f"  {k}: {v}" for k, v in stats["by_ioc_type"].items()
    ) or "  No data"

    verdict_lines = "\n".join(
        f"  {k}: {v}" for k, v in stats["by_verdict"].items()
    ) or "  No data"

    fb = stats["by_feedback"]
    total_fb = sum(fb.values()) if fb else 0
    if total_fb:
        fb_lines = "\n".join(
            f"  {k}: {v} ({round(v / total_fb * 100)}%)" for k, v in fb.items()
        )
    else:
        fb_lines = "  No feedback yet"

    top_lines = "\n".join(
        f"  {i + 1}. @{u['username']} — {u['count']} analyses"
        for i, u in enumerate(stats["top_users"])
    ) or "  No data"

    text = (
        f"📊 SOCrates Admin Dashboard\n\n"
        f"👥 Users\n"
        f"  Total: {stats['total_users']}\n"
        f"  Active (7d): {stats['active_users_7d']}\n\n"
        f"🔍 Analyses\n"
        f"  Today: {stats['analyses_today']}\n"
        f"  This week: {stats['analyses_week']}\n"
        f"  All time: {stats['analyses_total']}\n\n"
        f"📋 By IOC Type\n{ioc_lines}\n\n"
        f"⚖️ Verdicts\n{verdict_lines}\n\n"
        f"💬 Feedback\n{fb_lines}\n\n"
        f"🏆 Top 10 Users\n{top_lines}\n\n"
        f"📈 Avg analyses/user/day: {stats['avg_per_user_per_day']}"
    )

    for chunk in _chunk_message(text):
        await update.effective_message.reply_text(chunk)


# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------

SETUP_FIELDS = [
    "industry",
    "org_name",
    "cloud_providers",
    "tor_policy",
    "authorized_vpns",
    "unknown_vpn_policy",
    "never_block_ips",
    "own_infrastructure",
    "security_stack",
]

SETUP_LABELS = {
    "industry": "Industry",
    "org_name": "Organization name",
    "cloud_providers": "Cloud providers",
    "tor_policy": "Tor policy",
    "authorized_vpns": "Authorized VPNs",
    "unknown_vpn_policy": "Unknown VPN policy",
    "never_block_ips": "Never-block IPs",
    "own_infrastructure": "Own infrastructure",
    "security_stack": "Security stack",
}


def _setup_session_path(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    data_dir = context.bot_data["data_dir"]
    base = data_dir / "setup_sessions"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{chat_id}.json"


def _setup_save_state(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, state: dict[str, Any]
) -> None:
    if not state.get("origin_chat_id"):
        state["origin_chat_id"] = chat_id
    owner_user_id = state.get("owner_user_id")
    if owner_user_id:
        context.bot_data.setdefault("setup_active_by_user", {})[int(owner_user_id)] = int(chat_id)
    context.bot_data.setdefault("setup_sessions", {})[chat_id] = state
    path = _setup_session_path(context, chat_id)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _setup_clear_state(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    context.bot_data.get("setup_sessions", {}).pop(chat_id, None)
    active_by_user = context.bot_data.get("setup_active_by_user", {})
    for uid, active_chat_id in list(active_by_user.items()):
        try:
            if int(active_chat_id) == int(chat_id):
                active_by_user.pop(uid, None)
        except (TypeError, ValueError):
            active_by_user.pop(uid, None)
    path = _setup_session_path(context, chat_id)
    path.unlink(missing_ok=True)


def _setup_clear_user_sessions(
    context: ContextTypes.DEFAULT_TYPE, owner_user_id: int | None, keep_chat_id: int | None = None
) -> None:
    if not owner_user_id:
        return
    sessions = context.bot_data.get("setup_sessions", {})
    to_remove: list[int] = []
    for cid, state in sessions.items():
        if not isinstance(state, dict):
            continue
        if state.get("owner_user_id") != owner_user_id:
            continue
        origin_cid = int(state.get("origin_chat_id") or cid)
        if keep_chat_id is not None and origin_cid == keep_chat_id:
            continue
        to_remove.append(int(cid))
    for cid in to_remove:
        _setup_clear_state(context, cid)

    base = context.bot_data["data_dir"] / "setup_sessions"
    if not base.is_dir():
        return
    for path in base.glob("*.json"):
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(loaded, dict):
            continue
        if loaded.get("owner_user_id") != owner_user_id:
            continue
        try:
            origin_cid = int(loaded.get("origin_chat_id") or path.stem)
        except ValueError:
            origin_cid = 0
        if keep_chat_id is not None and origin_cid == keep_chat_id:
            continue
        path.unlink(missing_ok=True)


def _setup_state(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> dict[str, Any] | None:
    mem = context.bot_data.get("setup_sessions", {}).get(chat_id)
    if mem is not None:
        if mem.get("pending_custom"):
            mem["awaiting_custom_input"] = True
        return mem
    path = _setup_session_path(context, chat_id)
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    if loaded.get("editing_field") and loaded.get("status") != "editing":
        loaded["editing_field"] = None
    if loaded.get("pending_custom"):
        loaded["awaiting_custom_input"] = True
    if not loaded.get("origin_chat_id"):
        loaded["origin_chat_id"] = chat_id
    context.bot_data.setdefault("setup_sessions", {})[chat_id] = loaded
    return loaded



def _chunk_buttons(
    buttons: list[InlineKeyboardButton], per_row: int = 2
) -> list[list[InlineKeyboardButton]]:
    rows: list[list[InlineKeyboardButton]] = []
    i = 0
    while i < len(buttons):
        rows.append(buttons[i : i + per_row])
        i += per_row
    return rows


def _setup_question_config(step: int) -> dict[str, Any]:
    cfg: list[dict[str, Any]] = [
        {
            "type": "single",
            "field": "industry",
            "text": "Question 1/9: Select your industry",
            "options": ["finance", "healthcare", "education", "government", "tech", "ecommerce"],
            "labels": ["Finance", "Healthcare", "Education", "Government", "Tech", "Ecommerce"],
            "custom_prompt": "Type your answer:",
        },
        {
            "type": "text",
            "field": "org_name",
            "text": "Question 2/9: What is your organization's name?",
        },
        {
            "type": "multi",
            "field": "cloud_providers",
            "text": "Question 3/9: Select cloud providers (multi-select), then tap Done",
            "options": ["AWS", "Azure", "GCP", "None"],
            "custom_prompt": "Type your answer:",
        },
        {
            "type": "single",
            "field": "tor_policy",
            "text": "Question 4/9: What is your Tor policy?",
            "options": ["block", "monitor", "allow"],
            "labels": ["Block", "Monitor", "Allow"],
            "custom_prompt": "Type your answer:",
        },
        {
            "type": "single",
            "field": "authorized_vpns",
            "text": "Question 5/9: Authorized VPNs",
            "options": ["no_vpns"],
            "labels": ["No VPNs"],
            "custom_prompt": "Type your answer:\nList your authorized VPN IP ranges, comma-separated",
        },
        {
            "type": "single",
            "field": "unknown_vpn_policy",
            "text": "Question 6/9: Unknown/unauthorized VPN or proxy policy",
            "options": ["block", "monitor", "allow"],
            "labels": ["Block", "Monitor", "Allow"],
            "custom_prompt": "Type your answer:",
        },
        {
            "type": "single",
            "field": "never_block_ips",
            "text": "Question 7/9: Never-block IP ranges",
            "options": ["skip"],
            "labels": ["Skip"],
            "custom_prompt": (
                "Type your answer:\n"
                "List IP ranges or CIDRs that should never be blocked, comma-separated"
            ),
        },
        {
            "type": "single",
            "field": "own_infrastructure",
            "text": "Question 8/9: Own infrastructure IP ranges",
            "options": ["skip"],
            "labels": ["Skip"],
            "custom_prompt": (
                "Type your answer:\n"
                "List your own infrastructure IP ranges, comma-separated"
            ),
        },
        {
            "type": "multi",
            "field": "security_stack",
            "text": "Question 9/9: Select your security stack (multi-select), then tap Done",
            "options": [
                "CrowdStrike",
                "SentinelOne",
                "Palo Alto",
                "Fortinet",
                "Splunk",
                "Microsoft Sentinel",
                "Elastic",
            ],
            "custom_prompt": "Type your answer:",
        },
    ]
    return cfg[step]


def _setup_keyboard(state: dict[str, Any], chat_id: int) -> InlineKeyboardMarkup | None:
    cfg = _setup_question_config(state["step"])
    if cfg["type"] == "text":
        return None

    cid = chat_id
    step_token = int(state.get("step", 0))

    if cfg["type"] == "single":
        labels = cfg.get("labels") or cfg["options"]
        field = cfg["field"]
        current_value = state.get("answers", {}).get(field)

        def _single_selected(opt: str) -> bool:
            if field == "authorized_vpns" and opt == "no_vpns":
                return current_value == []
            if field in ("never_block_ips", "own_infrastructure") and opt == "skip":
                return current_value == []
            return current_value == opt

        buttons = [
            InlineKeyboardButton(
                f"{'✅ ' if _single_selected(opt) else ''}{lbl}",
                callback_data=f"s:{cid}:{step_token}:pick:{opt}",
            )
            for opt, lbl in zip(cfg["options"], labels)
        ]
        rows = _chunk_buttons(buttons, per_row=2)
        custom_checked = "✅ " if state.get("pending_custom") == field else ""
        rows.append(
            [
                InlineKeyboardButton(
                    f"{custom_checked}Custom",
                    callback_data=f"s:{cid}:{step_token}:custom",
                )
            ]
        )
        return InlineKeyboardMarkup(rows)

    selected = set(state.get("multi_selected") or [])
    buttons: list[InlineKeyboardButton] = []
    for opt in cfg["options"]:
        checked = "✅ " if opt in selected else ""
        buttons.append(
            InlineKeyboardButton(
                f"{checked}{opt}",
                callback_data=f"s:{cid}:{step_token}:toggle:{opt}",
            )
        )
    rows = _chunk_buttons(buttons, per_row=2)
    rows.append([InlineKeyboardButton("Custom", callback_data=f"s:{cid}:{step_token}:custom")])
    rows.append([InlineKeyboardButton("Done ✓", callback_data=f"s:{cid}:{step_token}:done")])
    return InlineKeyboardMarkup(rows)


async def _send_setup_question(
    msg, context: ContextTypes.DEFAULT_TYPE, chat_id: int
) -> None:
    state = _setup_state(context, chat_id)
    if not state:
        return
    cfg = _setup_question_config(state["step"])
    prompt_signature = (
        int(state.get("step", 0)),
        cfg["field"],
        str(state.get("status", "in_progress")),
        bool(state.get("pending_custom")),
    )
    if state.get("last_prompt_signature") == list(prompt_signature):
        return
    if cfg["type"] == "text":
        state["awaiting_custom_input"] = True
    elif not state.get("pending_custom"):
        state["awaiting_custom_input"] = False
    state["last_prompt_signature"] = list(prompt_signature)
    _setup_save_state(context, chat_id, state)
    kb = _setup_keyboard(state, chat_id)
    await msg.reply_text(cfg["text"], reply_markup=kb)
    if cfg["type"] == "text":
        await msg.reply_text("Type your answer:")


def _setup_parse_value(field: str, text: str) -> Any:
    if field in ("never_block_ips", "own_infrastructure", "authorized_vpns"):
        return parse_cidr_list(text)
    if field == "cloud_providers":
        return parse_cloud_list(text)
    if field == "security_stack":
        return parse_cloud_list(text)
    return text.strip()


def _build_profile_from_answers(chat_id: int, answers: dict[str, Any]) -> OrgProfile:
    return OrgProfile(
        chat_id=chat_id,
        industry=str(answers.get("industry", "")),
        org_name=str(answers.get("org_name", "")),
        cloud_providers=list(answers.get("cloud_providers") or []),
        tor_policy=str(answers.get("tor_policy", "")),
        authorized_vpns=list(answers.get("authorized_vpns") or []),
        unknown_vpn_policy=str(answers.get("unknown_vpn_policy", "")),
        never_block_ips=list(answers.get("never_block_ips") or []),
        own_infrastructure=list(answers.get("own_infrastructure") or []),
        security_stack=", ".join(answers.get("security_stack") or [])
        if isinstance(answers.get("security_stack"), list)
        else str(answers.get("security_stack", "")),
        custom_policies=[],
    )


async def _setup_show_summary(msg, context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    state = _setup_state(context, chat_id)
    if not state:
        return
    profile = _build_profile_from_answers(chat_id, state.get("answers", {}))
    cid = int(state.get("origin_chat_id") or chat_id)
    kb = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Confirm ✅", callback_data=f"s:{cid}:confirm"),
                InlineKeyboardButton("Redo 🔄", callback_data=f"s:{cid}:redo"),
            ],
            [InlineKeyboardButton("Edit specific field ✏️", callback_data=f"s:{cid}:edit")],
        ]
    )
    await msg.reply_html(
        "<b>Setup summary</b>\n\n"
        + format_profile_summary(profile)
        + "\n\nConfirm this profile?",
        reply_markup=kb,
    )


async def _setup_advance_or_summary(msg, context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    state = _setup_state(context, chat_id)
    if not state:
        return
    if state.get("editing_field") and state.get("status") == "editing":
        state["editing_field"] = None
        state["status"] = "confirm"
        state["last_prompt_signature"] = None
        _setup_save_state(context, chat_id, state)
        await _setup_show_summary(msg, context, chat_id)
        return
    state["step"] += 1
    if state["step"] >= len(SETUP_FIELDS):
        state["status"] = "confirm"
        state["last_prompt_signature"] = None
        _setup_save_state(context, chat_id, state)
        await _setup_show_summary(msg, context, chat_id)
        return
    state["last_prompt_signature"] = None
    _setup_save_state(context, chat_id, state)
    await _send_setup_question(msg, context, chat_id)


async def handle_setup_text_input(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    state: dict[str, Any] | None = None,
) -> None:
    msg = update.effective_message
    if not msg:
        return
    if state is None:
        chat_id = update.effective_chat.id
        state = _setup_state(context, chat_id)
        if not state:
            return
    chat_id = int(state.get("origin_chat_id") or update.effective_chat.id)
    cfg = _setup_question_config(state["step"])
    field = cfg["field"]

    pending = state.get("pending_custom")
    if pending:
        state["pending_custom"] = None
        state["awaiting_custom_input"] = False
        field = pending
        if field == "security_stack":
            existing = list(state["answers"].get(field) or [])
            existing.extend([s for s in parse_cloud_list(text) if s])
            state["answers"][field] = list(dict.fromkeys(existing))
        else:
            state["answers"][field] = _setup_parse_value(field, text)
        _setup_save_state(context, chat_id, state)
        await _setup_advance_or_summary(msg, context, chat_id)
        return

    if cfg["type"] == "text":
        state["answers"][field] = text.strip()
        _setup_save_state(context, chat_id, state)
        await _setup_advance_or_summary(msg, context, chat_id)


def _callback_chat_id_candidates(update: Update, q) -> list[int]:
    """Return unique non-zero chat_id integers extractable from a callback update."""
    seen: set[int] = set()
    result: list[int] = []
    for raw in [
        getattr(getattr(q, "message", None), "chat_id", None),
        getattr(getattr(getattr(q, "message", None), "chat", None), "id", None),
        getattr(getattr(update, "effective_chat", None), "id", None),
        getattr(getattr(q, "from_user", None), "id", None),
    ]:
        try:
            cid = int(raw)
            if cid and cid not in seen:
                seen.add(cid)
                result.append(cid)
        except (TypeError, ValueError):
            pass
    return result


async def handle_setup_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not q.data:
        return
    parts = q.data.split(":")
    if not parts or parts[0] != "s":
        return
    await q.answer()
    if not q.message:
        return

    chat_id: int | None = None
    state: dict[str, Any] | None = None

    try:
        embedded_cid = int(parts[1])
        if embedded_cid:
            st = _setup_state(context, embedded_cid)
            if st is not None:
                chat_id = embedded_cid
                state = st
    except (ValueError, IndexError):
        pass

    if state is None:
        for cid_candidate in _callback_chat_id_candidates(update, q):
            st = _setup_state(context, cid_candidate)
            if st is not None:
                chat_id = cid_candidate
                state = st
                break

    callback_chat_id = q.message.chat_id if q.message else None

    if state is None and q.from_user:
        uid = q.from_user.id
        for cid_key, st in context.bot_data.get("setup_sessions", {}).items():
            if (
                isinstance(st, dict)
                and st.get("owner_user_id") == uid
                and int(st.get("origin_chat_id") or cid_key) == int(callback_chat_id or 0)
            ):
                chat_id = int(cid_key)
                state = st
                break

    if state is None or chat_id is None:
        logger.warning("Setup callback: no active session found. data=%s", q.data)
        await q.answer("Session expired. Send /setup to begin.", show_alert=False)
        return

    chat_id = int(state.get("origin_chat_id") or chat_id)

    session_status = state.get("status", "in_progress")

    _action_keywords = {"pick", "toggle", "done", "custom", "confirm", "redo", "edit", "editfield"}
    start_idx = 1
    if len(parts) > 1 and parts[1].lstrip("-").isdigit():
        start_idx = 2

    callback_step: int | None = None
    if len(parts) > start_idx and parts[start_idx].lstrip("-").isdigit():
        callback_step = int(parts[start_idx])
        start_idx += 1

    action = parts[start_idx] if len(parts) > start_idx else ""
    _val_idx = start_idx + 1

    if action in {"pick", "toggle", "done", "custom"} and session_status == "confirm":
        logger.warning("Stale wizard callback %s on confirm-stage session, ignoring", action)
        await q.answer("Setup already complete. Confirm or Redo.", show_alert=False)
        return
    current_step = int(state.get("step", 0))
    if (
        callback_step is not None
        and action in {"pick", "toggle", "done", "custom"}
        and callback_step != current_step
    ):
        logger.warning(
            "Stale setup callback %s for step %s while session is at step %s",
            action,
            callback_step,
            current_step,
        )
        await q.answer("That button is from an older step. Use the latest setup message.", show_alert=False)
        return
    if action in {"confirm", "redo", "edit", "editfield"} and session_status != "confirm":
        logger.warning(
            "Ignoring summary callback %s while session status is %s",
            action,
            session_status,
        )
        await q.answer("Use the latest setup message.", show_alert=False)
        return
    if action == "confirm" and session_status != "confirm":
        logger.warning("Stale confirm callback on non-confirm session (status=%s), ignoring", session_status)
        await q.answer("", show_alert=False)
        return

    if action in {"pick", "toggle", "done", "custom"}:
        cfg = _setup_question_config(state["step"])
        field = cfg["field"]

        if action == "custom":
            state["pending_custom"] = field
            state["awaiting_custom_input"] = True
            _setup_save_state(context, chat_id, state)
            updated_kb = _setup_keyboard(state, chat_id)
            await _safe_edit_setup_markup(q, updated_kb)
            await q.message.reply_text(cfg.get("custom_prompt", "Type your answer:"))
            return

        if action == "pick":
            value = parts[_val_idx] if len(parts) > _val_idx else ""
            state["pending_custom"] = None
            state["awaiting_custom_input"] = False
            if field == "authorized_vpns" and value == "no_vpns":
                state["answers"][field] = []
            elif field in ("never_block_ips", "own_infrastructure") and value == "skip":
                state["answers"][field] = []
            else:
                state["answers"][field] = value
            _setup_save_state(context, chat_id, state)
            updated_kb = _setup_keyboard(state, chat_id)
            await _safe_edit_setup_markup(q, updated_kb)
            await _setup_advance_or_summary(q.message, context, chat_id)
            return

        if action == "toggle":
            value = parts[_val_idx] if len(parts) > _val_idx else ""
            selected = set(state.get("multi_selected") or [])
            if field == "cloud_providers" and value == "None":
                selected = {"None"} if value not in selected else set()
            else:
                selected.discard("None")
                if value in selected:
                    selected.remove(value)
                else:
                    selected.add(value)
            state["multi_selected"] = list(selected)
            _setup_save_state(context, chat_id, state)
            updated_kb = _setup_keyboard(state, chat_id)
            await _safe_edit_setup_markup(q, updated_kb)
            return

        if action == "done":
            selected = list(dict.fromkeys(state.get("multi_selected") or []))
            state["multi_selected"] = []
            state["awaiting_custom_input"] = False
            state["answers"][field] = selected
            _setup_save_state(context, chat_id, state)
            await _setup_advance_or_summary(q.message, context, chat_id)
            return

    if action == "confirm":
        profile = _build_profile_from_answers(chat_id, state.get("answers", {}))
        await save_profile(profile)
        _setup_clear_state(context, chat_id)
        await q.message.reply_text(
            "Profile saved. Use /profile to view or paste an IOC to analyze."
        )
        return

    if action == "redo":
        state["step"] = 0
        state["answers"] = {}
        state["pending_custom"] = None
        state["awaiting_custom_input"] = False
        state["multi_selected"] = []
        state["status"] = "in_progress"
        state["editing_field"] = None
        state["last_prompt_signature"] = None
        _setup_save_state(context, chat_id, state)
        await _send_setup_question(q.message, context, chat_id)
        return

    if action == "edit":
        rows = []
        for field in SETUP_FIELDS:
            rows.append(
                [
                    InlineKeyboardButton(
                        SETUP_LABELS.get(field, field),
                        callback_data=f"s:{chat_id}:editfield:{field}",
                    )
                ]
            )
        await q.message.reply_text(
            "Choose a field to edit:",
            reply_markup=InlineKeyboardMarkup(rows),
        )
        return

    if action == "editfield" and len(parts) > _val_idx:
        field = parts[_val_idx]
        if field not in SETUP_FIELDS:
            await q.message.reply_text("Unknown field.")
            return
        state["step"] = SETUP_FIELDS.index(field)
        state["editing_field"] = field
        state["pending_custom"] = None
        state["awaiting_custom_input"] = False
        state["multi_selected"] = []
        state["status"] = "editing"
        state["last_prompt_signature"] = None
        _setup_save_state(context, chat_id, state)
        await _send_setup_question(q.message, context, chat_id)


# ---------------------------------------------------------------------------
# Feedback handlers
# ---------------------------------------------------------------------------

async def handle_feedback_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not q.data:
        return
    parts = q.data.split(":")
    if len(parts) < 3 or parts[0] != "f":
        await q.answer("Invalid button", show_alert=False)
        return
    action, decision_id = parts[1], parts[2]
    chat_id = q.message.chat_id if q.message else 0

    if action == "agree":
        await update_feedback(chat_id, decision_id, feedback="agree")
        feedback_total.labels(feedback_type="agree").inc()
        await q.answer("✅ Feedback saved. Thanks!")
        return

    fp = context.bot_data.setdefault("feedback_pending", {})
    if action == "disagree":
        await update_feedback(chat_id, decision_id, feedback="disagree")
        feedback_total.labels(feedback_type="disagree").inc()
        fp[chat_id] = {"kind": "feedback_note", "decision_id": decision_id}
        await q.answer()
        if q.message:
            await q.message.reply_text(
                "What was wrong with the verdict? Reply with a short note."
            )
        return
    if action == "partial":
        await update_feedback(chat_id, decision_id, feedback="partial")
        feedback_total.labels(feedback_type="partial").inc()
        fp[chat_id] = {"kind": "feedback_partial", "decision_id": decision_id}
        await q.answer()
        if q.message:
            await q.message.reply_text("What was correct and what should change?")
        return
    if action == "note":
        fp[chat_id] = {"kind": "action_note", "decision_id": decision_id}
        await q.answer()
        if q.message:
            await q.message.reply_text(
                "What action did you take? (e.g. blocked 4h, whitelisted, monitoring)"
            )


async def handle_feedback_pending_text(
    update: Update, context: ContextTypes.DEFAULT_TYPE, pending: dict[str, Any], text: str
) -> None:
    chat_id = update.effective_chat.id
    decision_id = pending["decision_id"]
    kind = pending["kind"]
    context.bot_data["feedback_pending"].pop(chat_id, None)
    if kind == "feedback_note":
        await update_feedback(chat_id, decision_id, note=text)
    elif kind == "feedback_partial":
        await update_feedback(chat_id, decision_id, note=text)
    elif kind == "action_note":
        await update_feedback(chat_id, decision_id, action_taken=text)
    if update.effective_message:
        await update.effective_message.reply_text("Saved.")


async def handle_dialogue_reply(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    sess: Any,
    text: str,
) -> None:
    chat_id = update.effective_chat.id
    answer = text.strip()
    if not answer:
        if update.effective_message:
            await update.effective_message.reply_text("Please send an answer or /skip.")
        return

    sess.analyst_responses.append(answer)
    answered = len(sess.analyst_responses)
    total = len(sess.followup_questions)
    if answered < total:
        await put_session(sess)
        next_q = sess.followup_questions[answered]
        if update.effective_message:
            await update.effective_message.reply_text(
                f"Thanks. Question {answered + 1}/{total}: {next_q}"
            )
        return

    org_block = await build_org_context(chat_id)
    entry = sess.enrichment_data
    past_block = ""
    if entry:
        sim = await find_similar_decisions(
            chat_id,
            entry.get("kind", ""),
            str(entry.get("ioc", "")),
            entry,
        )
        past_block = format_past_decisions_for_llm(sim)
    flags_str = ", ".join(sess.ambiguity_flags)
    qa_pairs = []
    for idx, question in enumerate(sess.followup_questions):
        response = sess.analyst_responses[idx] if idx < len(sess.analyst_responses) else ""
        qa_pairs.append(f"Q{idx + 1}: {question}\nA{idx + 1}: {response}")
    ans = "\n".join(qa_pairs)
    follow = (
        "ANALYST PROVIDED ADDITIONAL CONTEXT:\n"
        f"- Ambiguity detected: {flags_str}\n"
        f"{ans}\n"
        "Given this context and enrichment, give a SPECIFIC, ACTIONABLE verdict."
    )
    await clear_session(chat_id)
    await _run_llm_pipeline(
        update,
        context,
        sess.payload,
        entry=entry,
        chat_id=chat_id,
        org_block=org_block,
        past_block=past_block,
        followup_block=follow,
        ambiguity_flags=sess.ambiguity_flags,
    )


def _find_setup_state(context: ContextTypes.DEFAULT_TYPE, update: Update) -> dict[str, Any] | None:
    """Find the current chat's setup session and avoid drifting into stale sessions."""
    chat_id = update.effective_chat.id
    st = _setup_state(context, chat_id)
    if st is not None:
        return st
    uid = update.effective_user.id if update.effective_user else None
    if uid:
        active_chat_id = context.bot_data.get("setup_active_by_user", {}).get(int(uid))
        try:
            if active_chat_id is not None:
                st = _setup_state(context, int(active_chat_id))
                if st is not None:
                    return st
        except (TypeError, ValueError):
            pass
    sessions_map = context.bot_data.get("setup_sessions", {})
    for st in sessions_map.values():
        if isinstance(st, dict) and int(st.get("origin_chat_id") or 0) == chat_id:
            return st
    if uid:
        for st in sessions_map.values():
            if (
                isinstance(st, dict)
                and st.get("owner_user_id") == uid
                and int(st.get("origin_chat_id") or 0) == chat_id
            ):
                return st
        for st in sessions_map.values():
            if (
                isinstance(st, dict)
                and st.get("owner_user_id") == uid
                and str(st.get("status", "in_progress")) != "confirm"
            ):
                return st
    base = context.bot_data["data_dir"] / "setup_sessions"
    if base.is_dir():
        for f in base.iterdir():
            if not f.suffix == ".json":
                continue
            try:
                cid = int(f.stem)
            except ValueError:
                continue
            if cid in sessions_map:
                continue
            loaded = _setup_state(context, cid)
            if loaded and int(loaded.get("origin_chat_id") or 0) == chat_id:
                return loaded
            if (
                loaded
                and uid
                and loaded.get("owner_user_id") == uid
                and int(loaded.get("origin_chat_id") or 0) == chat_id
            ):
                return loaded
            if (
                loaded
                and uid
                and loaded.get("owner_user_id") == uid
                and str(loaded.get("status", "in_progress")) != "confirm"
            ):
                return loaded
    return None


def _has_incomplete_setup_session(
    context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int | None
) -> bool:
    sessions_map = context.bot_data.get("setup_sessions", {})
    for st in sessions_map.values():
        if not isinstance(st, dict):
            continue
        if str(st.get("status", "in_progress")) == "confirm":
            continue
        if int(st.get("origin_chat_id") or 0) == chat_id:
            return True
        if user_id and st.get("owner_user_id") == user_id:
            return True

    base = context.bot_data["data_dir"] / "setup_sessions"
    if not base.is_dir():
        return False
    for path in base.glob("*.json"):
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(loaded, dict):
            continue
        if str(loaded.get("status", "in_progress")) == "confirm":
            continue
        if int(loaded.get("origin_chat_id") or 0) == chat_id:
            return True
        if user_id and loaded.get("owner_user_id") == user_id:
            return True
    return False


async def _safe_edit_setup_markup(q, reply_markup: InlineKeyboardMarkup | None) -> None:
    if reply_markup is None:
        return
    with contextlib.suppress(TelegramError):
        await q.edit_message_reply_markup(reply_markup=reply_markup)


# ---------------------------------------------------------------------------
# Main text handler
# ---------------------------------------------------------------------------

async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    if not msg or not msg.text:
        return
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id if update.effective_user else None
    user_text = msg.text.strip()
    if not user_text:
        return

    # --- SETUP SESSION GUARD (highest priority, single block) ---
    setup_st = _find_setup_state(context, update)
    logger.info(
        "on_text chat=%s text=%r setup_found=%s step=%s status=%s awaiting=%s",
        chat_id,
        user_text[:30],
        setup_st is not None,
        setup_st.get("step") if setup_st else None,
        setup_st.get("status") if setup_st else None,
        setup_st.get("awaiting_custom_input") if setup_st else None,
    )
    if setup_st is not None:
        step = setup_st.get("step", 0)
        status = setup_st.get("status", "in_progress")
        if status == "confirm" or step >= len(SETUP_FIELDS):
            await msg.reply_text("Setup is waiting for your buttons. Use Confirm, Redo, or Edit specific field.")
            return
        if setup_st.get("awaiting_custom_input") or setup_st.get("pending_custom"):
            await handle_setup_text_input(update, context, user_text, state=setup_st)
            return
        try:
            cfg = _setup_question_config(step)
        except (IndexError, KeyError):
            logger.error("on_text: invalid setup step %s, clearing session", step)
            origin = int(setup_st.get("origin_chat_id") or chat_id)
            _setup_clear_state(context, origin)
            await msg.reply_text("Setup session was reset. Send /setup to begin again.")
            return
        if cfg["type"] == "text":
            await handle_setup_text_input(update, context, user_text, state=setup_st)
            return
        await msg.reply_text(
            "Please use the buttons for this step, or tap Custom before typing your answer."
        )
        return

    if _has_incomplete_setup_session(context, chat_id, user_id):
        await msg.reply_text(
            "Setup is still in progress. Please continue the setup steps instead of sending analysis input."
        )
        return

    # 2) Dialogue follow-up session.
    sess = await get_session(chat_id)
    if sess and sess.status == "awaiting_followup":
        await handle_dialogue_reply(update, context, sess, user_text)
        return

    # 3) Pending feedback note.
    fp = context.bot_data.get("feedback_pending", {}).get(chat_id)
    if fp:
        await handle_feedback_pending_text(update, context, fp, user_text)
        return

    # 4) Normal IOC detection and analysis.
    await process_ioc_pipeline(update, context, user_text)


# ---------------------------------------------------------------------------
# Application bootstrap
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = load_config()
    vt = VirusTotalClient(cfg.virustotal_api_key, timeout=cfg.http_timeout_seconds)
    abuse = AbuseIPDBClient(cfg.abuseipdb_api_key, timeout=cfg.http_timeout_seconds)
    shodan = ShodanClient(cfg.shodan_api_key, timeout=cfg.http_timeout_seconds)
    urlscan = UrlscanClient(cfg.urlscan_api_key, timeout=cfg.http_timeout_seconds)
    otx = OTXClient(cfg.otx_api_key, timeout=cfg.http_timeout_seconds)

    # Start Prometheus metrics server (non-blocking background thread)
    start_metrics_server()

    async def post_init(application: Application) -> None:
        await init_db(cfg.database_url)
        logger.info("Database ready")

    async def post_shutdown(application: Application) -> None:
        await close_db()

    request = HTTPXRequest(
        connect_timeout=45.0,
        read_timeout=45.0,
        write_timeout=45.0,
        pool_timeout=10.0,
    )
    app = (
        Application.builder()
        .token(cfg.telegram_bot_token)
        .request(request)
        .concurrent_updates(False)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.bot_data["config"] = cfg
    app.bot_data["vt"] = vt
    app.bot_data["abuse"] = abuse
    app.bot_data["shodan"] = shodan
    app.bot_data["urlscan"] = urlscan
    app.bot_data["otx"] = otx
    app.bot_data["data_dir"] = cfg.data_dir
    app.bot_data["feedback_pending"] = {}
    app.bot_data["setup_sessions"] = {}
    app.bot_data["setup_active_by_user"] = {}

    # User tracking middleware — runs for every update before other handlers
    app.add_handler(TypeHandler(Update, track_user_update), group=-1)

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("setup", cmd_setup))
    app.add_handler(CommandHandler("profile", cmd_profile))
    app.add_handler(CommandHandler("addpolicy", cmd_addpolicy))
    app.add_handler(CommandHandler("clearpolicy", cmd_clearpolicy))
    app.add_handler(CommandHandler("skip", cmd_skip))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(CommandHandler("clearhistory", cmd_clearhistory))
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CallbackQueryHandler(handle_setup_callback, pattern=r"^s:"))
    app.add_handler(CallbackQueryHandler(handle_feedback_callback, pattern=r"^f:"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    logger.info("SOCrates starting (polling)")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
