import asyncio
import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _install_test_stubs() -> None:
    telegram = types.ModuleType("telegram")

    class InlineKeyboardButton:
        def __init__(self, text, callback_data=None):
            self.text = text
            self.callback_data = callback_data

    class InlineKeyboardMarkup:
        def __init__(self, inline_keyboard):
            self.inline_keyboard = inline_keyboard

    class InputFile:
        def __init__(self, *args, **kwargs):
            pass

    class Update:
        pass

    telegram.InlineKeyboardButton = InlineKeyboardButton
    telegram.InlineKeyboardMarkup = InlineKeyboardMarkup
    telegram.InputFile = InputFile
    telegram.Update = Update
    sys.modules["telegram"] = telegram

    telegram_constants = types.ModuleType("telegram.constants")
    telegram_constants.ChatAction = types.SimpleNamespace(TYPING="typing")
    sys.modules["telegram.constants"] = telegram_constants

    telegram_error = types.ModuleType("telegram.error")

    class TelegramError(Exception):
        pass

    telegram_error.TelegramError = TelegramError
    sys.modules["telegram.error"] = telegram_error

    telegram_ext = types.ModuleType("telegram.ext")
    telegram_ext.Application = type(
        "Application",
        (),
        {"builder": classmethod(lambda cls: (_ for _ in ()).throw(RuntimeError("unused")))},
    )
    telegram_ext.CallbackQueryHandler = lambda *args, **kwargs: None
    telegram_ext.CommandHandler = lambda *args, **kwargs: None
    telegram_ext.MessageHandler = lambda *args, **kwargs: None
    telegram_ext.ContextTypes = types.SimpleNamespace(DEFAULT_TYPE=object)
    telegram_ext.filters = types.SimpleNamespace(TEXT=1, COMMAND=2)
    sys.modules["telegram.ext"] = telegram_ext

    telegram_request = types.ModuleType("telegram.request")
    telegram_request.HTTPXRequest = lambda *args, **kwargs: None
    sys.modules["telegram.request"] = telegram_request

    stub_modules = {
        "analyzer": {"analyze_enrichment": lambda *args, **kwargs: ("", "stub")},
        "config": {"load_config": lambda: None},
        "detector": {"InputKind": object, "detect_input": lambda text: None},
        "dialogue.ambiguity": {
            "detect_ambiguity": lambda *args, **kwargs: [],
            "first_enriched_entry": lambda payload: None,
        },
        "dialogue.followup": {
            "format_preliminary": lambda *args, **kwargs: "",
            "generate_followups": lambda *args, **kwargs: [],
        },
        "dialogue.session": {
            "SessionState": object,
            "clear_session": lambda *args, **kwargs: None,
            "get_session": lambda *args, **kwargs: None,
            "put_session": lambda *args, **kwargs: None,
        },
        "enrichers.abuseipdb": {"AbuseIPDBClient": object},
        "enrichers.otx": {"OTXClient": object},
        "enrichers.shodan_client": {"ShodanClient": object},
        "enrichers.urlscan": {"UrlscanClient": object},
        "enrichers.virustotal": {"VirusTotalClient": object},
        "formatter": {"format_telegram_report": lambda *args, **kwargs: ""},
        "ioc_extractor": {
            "extract_iocs_from_text": lambda *args, **kwargs: [],
            "is_public_routable_ip": lambda *args, **kwargs: True,
            "placeholder_ioc_note": lambda *args, **kwargs: "",
        },
        "memory.feedback": {
            "create_decision_record": lambda *args, **kwargs: None,
            "update_feedback": lambda *args, **kwargs: None,
        },
        "memory.models": {"DecisionRecord": object},
        "memory.retriever": {
            "build_enrichment_summary": lambda *args, **kwargs: "",
            "find_similar_decisions": lambda *args, **kwargs: [],
            "format_past_decisions_for_llm": lambda *args, **kwargs: "",
        },
        "memory.store": {
            "clear_all_decisions": lambda *args, **kwargs: None,
            "load_all_decisions": lambda *args, **kwargs: [],
            "parse_verdict_lines": lambda *args, **kwargs: ("", ""),
            "save_decision": lambda *args, **kwargs: None,
        },
        "org_profile.context_builder": {
            "apply_org_match_to_entry": lambda *args, **kwargs: None,
            "apply_vpn_proxy_policy": lambda *args, **kwargs: None,
            "build_org_context": lambda *args, **kwargs: "",
            "format_profile_summary": lambda profile: "summary",
        },
        "org_profile.models": {
            "OrgProfile": type(
                "OrgProfile",
                (object,),
                {"__init__": lambda self, **kwargs: self.__dict__.update(kwargs)},
            )
        },
        "org_profile.storage": {
            "load_profile": lambda *args, **kwargs: None,
            "parse_cidr_list": lambda text: [
                item.strip()
                for item in text.replace(";", ",").split(",")
                if item.strip()
            ]
            if text.strip().lower() not in ("", "skip")
            else [],
            "parse_cloud_list": lambda text: [
                item.strip()
                for item in text.replace(";", ",").split(",")
                if item.strip()
            ]
            if text.strip().lower() not in ("", "skip", "none")
            else [],
            "save_profile": lambda *args, **kwargs: None,
        },
    }

    for name, attrs in stub_modules.items():
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        sys.modules[name] = module


_install_test_stubs()
sys.path.insert(0, str(ROOT))
bot = importlib.import_module("bot")


class FakeMessage:
    def __init__(self, chat_id: int):
        self.chat_id = chat_id
        self.chat = types.SimpleNamespace(id=chat_id)
        self.replies: list[str] = []
        self.reply_markups = []
        self.text = None

    async def reply_text(self, text, reply_markup=None):
        self.replies.append(text)
        self.reply_markups.append(reply_markup)

    async def reply_html(self, text, reply_markup=None):
        self.replies.append(text)
        self.reply_markups.append(reply_markup)


class FakeQuery:
    def __init__(self, data: str, message: FakeMessage, user_id: int = 42):
        self.data = data
        self.message = message
        self.from_user = types.SimpleNamespace(id=user_id)
        self.answered = []
        self.edits = []

    async def answer(self, text="", show_alert=False):
        self.answered.append((text, show_alert))

    async def edit_message_reply_markup(self, reply_markup=None):
        self.edits.append(reply_markup)


class FakeUpdate:
    def __init__(self, chat_id=100, user_id=42, message=None, query=None, text=None):
        self.effective_chat = types.SimpleNamespace(id=chat_id)
        self.effective_user = types.SimpleNamespace(id=user_id)
        self.effective_message = message
        self.callback_query = query
        if message is not None and text is not None:
            message.text = text


class FakeContext:
    def __init__(self, data_dir: str):
        self.bot_data = {
            "data_dir": Path(data_dir),
            "setup_sessions": {},
            "setup_active_by_user": {},
            "feedback_pending": {},
        }


class SetupFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.context = FakeContext(self.tempdir)
        self.chat_id = 100
        self.user_id = 42
        start_message = FakeMessage(self.chat_id)
        start_update = FakeUpdate(chat_id=self.chat_id, user_id=self.user_id, message=start_message)
        await bot.cmd_setup(start_update, self.context)

    def _state(self):
        return bot._setup_state(self.context, self.chat_id)

    async def _click_current(self, action: str, value: str | None = None):
        state = self._state()
        step = state["step"]
        data = f"s:{self.chat_id}:{step}:{action}"
        if value is not None:
            data += f":{value}"
        message = FakeMessage(self.chat_id)
        query = FakeQuery(data, message, user_id=self.user_id)
        update = FakeUpdate(
            chat_id=self.chat_id,
            user_id=self.user_id,
            message=message,
            query=query,
        )
        await bot.handle_setup_callback(update, self.context)
        return message, query, self._state()

    async def _send_text(self, text: str):
        message = FakeMessage(self.chat_id)
        update = FakeUpdate(
            chat_id=self.chat_id,
            user_id=self.user_id,
            message=message,
            text=text,
        )
        await bot.on_text(update, self.context)
        return message, self._state()

    async def test_full_setup_flow_stays_inside_wizard(self):
        _, _, state = await self._click_current("pick", "finance")
        self.assertEqual(state["step"], 1)

        _, state = await self._send_text("Acme")
        self.assertEqual(state["step"], 2)

        _, _, state = await self._click_current("toggle", "AWS")
        self.assertEqual(state["multi_selected"], ["AWS"])
        _, _, state = await self._click_current("done")
        self.assertEqual(state["step"], 3)

        _, _, state = await self._click_current("pick", "block")
        self.assertEqual(state["step"], 4)

        _, _, state = await self._click_current("pick", "no_vpns")
        self.assertEqual(state["step"], 5)
        self.assertEqual(state["answers"]["authorized_vpns"], [])

        _, _, state = await self._click_current("pick", "monitor")
        self.assertEqual(state["step"], 6)

        _, _, state = await self._click_current("pick", "skip")
        self.assertEqual(state["step"], 7)

        _, _, state = await self._click_current("custom")
        self.assertEqual(state["pending_custom"], "own_infrastructure")
        text_message, state = await self._send_text("2.2.2.0/24,3.3.3.0/24")
        self.assertEqual(state["step"], 8)
        self.assertEqual(text_message.replies, ["Question 9/9: Select your security stack (multi-select), then tap Done"])

        _, _, state = await self._click_current("custom")
        self.assertEqual(state["pending_custom"], "security_stack")
        text_message, state = await self._send_text("Palo Alto, Elastic")
        self.assertEqual(state["status"], "confirm")
        self.assertTrue(any("Setup summary" in reply for reply in text_message.replies))

    async def test_incomplete_setup_blocks_ioc_analysis(self):
        _, _, state = await self._click_current("pick", "finance")
        self.assertEqual(state["step"], 1)
        _, state = await self._send_text("Acme")
        self.assertEqual(state["step"], 2)

        warning_message = FakeMessage(self.chat_id)
        update = FakeUpdate(
            chat_id=self.chat_id,
            user_id=self.user_id,
            message=warning_message,
            text="8.8.8.8",
        )
        await bot.on_text(update, self.context)
        self.assertTrue(warning_message.replies)
        self.assertIn("tap Custom before typing your answer", warning_message.replies[-1])

    async def test_single_choice_buttons_show_tick(self):
        _, _, state = await self._click_current("pick", "finance")
        self.assertEqual(state["step"], 1)
        _, state = await self._send_text("Acme")
        self.assertEqual(state["step"], 2)
        _, _, state = await self._click_current("toggle", "AWS")
        _, _, state = await self._click_current("done")
        self.assertEqual(state["step"], 3)

        _, query, state = await self._click_current("pick", "block")
        keyboard = query.edits[-1]
        labels = [button.text for row in keyboard.inline_keyboard for button in row]
        self.assertIn("✅ Block", labels)

        _, query, state = await self._click_current("pick", "no_vpns")
        keyboard = query.edits[-1]
        labels = [button.text for row in keyboard.inline_keyboard for button in row]
        self.assertIn("✅ No VPNs", labels)

    async def test_redo_restarts_cleanly(self):
        _, _, state = await self._click_current("pick", "finance")
        _, state = await self._send_text("Acme")
        _, _, state = await self._click_current("toggle", "AWS")
        _, _, state = await self._click_current("done")
        _, _, state = await self._click_current("pick", "block")
        _, _, state = await self._click_current("pick", "no_vpns")
        _, _, state = await self._click_current("pick", "monitor")
        _, _, state = await self._click_current("pick", "skip")
        _, _, state = await self._click_current("custom")
        _, state = await self._send_text("2.2.2.0/24")
        _, _, state = await self._click_current("toggle", "Palo Alto")
        _, _, state = await self._click_current("done")
        self.assertEqual(state["status"], "confirm")

        summary_message = FakeMessage(self.chat_id)
        query = FakeQuery(f"s:{self.chat_id}:redo", summary_message, user_id=self.user_id)
        update = FakeUpdate(
            chat_id=self.chat_id,
            user_id=self.user_id,
            message=summary_message,
            query=query,
        )
        await bot.handle_setup_callback(update, self.context)
        state = self._state()
        self.assertEqual(state["step"], 0)
        self.assertEqual(state["status"], "in_progress")

        _, _, state = await self._click_current("pick", "education")
        self.assertEqual(state["step"], 1)
        _, state = await self._send_text("Redo Org")
        self.assertEqual(state["step"], 2)


if __name__ == "__main__":
    unittest.main()
