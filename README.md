# SOCrates (AI SOC Agent)

Telegram bot **SOCrates** — an AI SOC teammate. It enriches IOCs via VirusTotal, AbuseIPDB, and Shodan, then asks an LLM (Claude or OpenAI) for a structured verdict.

**Adaptive features:** per-chat **organization profile** (`/setup`), **clarifying questions** when enrichment is ambiguous, and **decision memory** with inline feedback (✅/❌) plus `/history`, `/stats`, and `/export`. Data is stored under `data/` (JSON files; set `DATA_DIR` to override).

## Requirements

- Python **3.11+**
- Telegram bot token ([BotFather](https://t.me/BotFather))
- [VirusTotal](https://www.virustotal.com/gui/join-us) API key (required)
- [AbuseIPDB](https://www.abuseipdb.com/) and [Shodan](https://www.shodan.io/) keys optional but recommended for IP context
- **Anthropic** and/or **OpenAI** API key (at least one)

## Setup

```bash
git clone https://github.com/arch1tect1/socrates.git
cd socrates
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
copy .env.example .env            # Windows — fill in secrets
# cp .env.example .env            # Linux/macOS
```

Edit `.env` with your keys. Required: `TELEGRAM_BOT_TOKEN`, `VIRUSTOTAL_API_KEY`, and either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.

If Anthropic returns **404 / `not_found_error` for `model`**, your `CLAUDE_MODEL` is invalid or retired — set `CLAUDE_MODEL` to a [current model ID](https://docs.anthropic.com/en/docs/about-claude/models) (the default in code is updated when defaults change).

## Run

From the repository root:

```bash
python bot.py
```

On **Windows**, if `python` comes from Git Bash / MSYS (`/usr/bin/python.exe`) you may get `ModuleNotFoundError: No module named 'telegram'`. Use the real Windows interpreter instead:

```powershell
py -3 -m pip install -r requirements.txt
py -3 bot.py
```

In Telegram, open your bot and send `/start`, then paste an IOC or log line.

`.env` can live in the project directory or one level up; both are loaded.

## Deploy on a cloud server (Docker recommended)

The bot uses **long polling** — it only needs **outbound HTTPS** to Telegram and your APIs (no public inbound port or webhook required).

### Option A — Docker Compose (any Linux VPS)

On the server (Ubuntu/Debian example):

```bash
# Install Docker + Compose plugin (see docs.docker.com) then:
mkdir -p ~/socrates && cd ~/socrates
# Upload this folder (scp/rsync/git) so Dockerfile and docker-compose.yml are here.
cp .env.example .env && nano .env   # fill secrets — never commit .env

docker compose up -d --build
docker compose logs -f              # verify "SOCrates starting (polling)"
```

Compose sets `DATA_DIR=/app/data` and a **named volume** so profiles and decisions survive container restarts.

- **One instance only** — two processes with the same `TELEGRAM_BOT_TOKEN` cause `409 Conflict` on `getUpdates`.
- **Firewall** — allow outbound HTTPS (default); no need to open port 443 *inbound* for polling.

### Option B — systemd + venv (no Docker)

See `deploy/socrates-bot.service.example`: create a venv, install `requirements.txt`, point `WorkingDirectory` and `ExecStart` at your install path, then `systemctl enable --now socrates-bot`.

### Moving secrets

Copy `.env` securely (e.g. `scp .env user@server:~/socrates/.env`). On the server: `chmod 600 .env`.

## Commands

| Command | Description |
|--------|-------------|
| `/start` | Welcome + quick tips |
| `/help` | All commands and inputs |
| `/setup` | Guided org profile (industry, cloud, Tor/VPN policy, CIDRs, stack) |
| `/profile` | Show saved org profile |
| `/addpolicy` | Append a custom policy line (natural language) |
| `/clearpolicy` | Remove all custom policies |
| `/skip` | During follow-up questions: force best-effort verdict without answers |
| `/history` | Last 10 decisions; optional `/history 185.x.x.x` to filter |
| `/stats` | Counts of stored decisions and feedback |
| `/export` | Download decisions as CSV |
| `/clearhistory yes` | Delete all decisions for this chat |

## Behavior

1. **Detection** — Standalone IPv4/IPv6, MD5/SHA1/SHA256, or domain; otherwise **raw log** with regex IOC extraction.
2. **Org profile** — Never-block / own-infra CIDRs add `org_match` on IPs; context is injected into the LLM when a profile exists.
3. **Ambiguity mode** — For a **single** enriched IOC, if rules fire (cloud/Tor/mixed VT/org-protected/VPN/low abuse score), the bot asks clarifying questions first; reply in chat or `/skip`.
4. **Memory** — After each verdict, inline buttons store feedback; similar past cases are summarized for the model.
5. **Enrichment** — VirusTotal for all IOC types; AbuseIPDB + Shodan for public IPs. Failed APIs are noted in the payload.
6. **Rate limiting** — VirusTotal free tier: **4 requests/minute** (sliding window).
7. **Timeouts** — HTTP clients use **30s** per request (Telegram client uses longer connect/read timeouts).
8. **Typing** — Chat action “typing” while working.

## Project layout

```
socrates/
├── bot.py
├── config.py
├── detector.py
├── enrichers/
├── org_profile/       # profile JSON + LLM context + CIDR matching
├── dialogue/          # ambiguity, sessions, follow-up questions
├── memory/            # decisions, similarity, feedback helpers
├── analyzer.py
├── formatter.py
├── ioc_extractor.py
├── data/              # runtime: profiles/ decisions/ (gitignored contents)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── deploy/
├── .env.example
└── README.md
```

## Security notes

- Do not commit `.env` or real API keys.
- IOCs and logs are sent to third-party APIs and to your chosen LLM provider; use only data you are allowed to share under your org’s policy.
