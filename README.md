# SOCrates (AI SOC Agent)

Telegram bot: **AI SOC Agent** — an AI-powered security analyst assistant. Users send IOCs (IPs, domains, hashes) or raw logs; the bot enriches them via VirusTotal, AbuseIPDB (IPs), and Shodan (IPs), then asks an LLM (Claude or OpenAI) for a structured SOC-style verdict.

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
docker compose logs -f              # verify "starting (polling)"
```

- **One instance only** — two processes with the same `TELEGRAM_BOT_TOKEN` cause `409 Conflict` on `getUpdates`.
- **Firewall** — allow outbound HTTPS (default); no need to open port 443 *inbound* for polling.

### Option B — systemd + venv (no Docker)

See `deploy/socrates-bot.service.example`: create a venv, install `requirements.txt`, point `WorkingDirectory` and `ExecStart` at your install path, then `systemctl enable --now socrates-bot`.

### Moving secrets

Copy `.env` securely (e.g. `scp .env user@server:~/socrates/.env`). On the server: `chmod 600 .env`.

## Commands

| Command   | Description                                      |
|----------|---------------------------------------------------|
| `/start` | Short usage instructions                          |
| `/help`  | Supported input types and tips                    |

## Behavior

1. **Detection** — Standalone IPv4/IPv6, MD5/SHA1/SHA256, or domain; otherwise the message is treated as **raw log** and IOCs are extracted with regex.
2. **Enrichment** — VirusTotal for all IOC types; AbuseIPDB + Shodan only for IPs. Failed APIs are noted in the payload; others continue.
3. **Rate limiting** — VirusTotal free tier: **4 requests per minute** (sliding window) enforced in code.
4. **Timeouts** — HTTP clients use a **30s** timeout per request.
5. **Typing** — A typing indicator is refreshed while enrichment and LLM calls run.

## Project layout

```
socrates/
├── bot.py
├── config.py
├── detector.py
├── enrichers/
├── analyzer.py
├── formatter.py
├── ioc_extractor.py
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
