# SentinelScope 🛡️ (Telegram Security Bot)

A Telegram bot that performs URL reputation scanning using VirusTotal, with secure secret management, input validation, rate limiting, and audit logging.

## Features
- `/start`, `/help`
- `/scan_url <url>` — VirusTotal URL reputation + verdict
- Rate limiting (per-user)
- Audit logging to `bot.log`
- Secrets stored in `.env` (never committed)

## Tech Stack
- Python
- python-telegram-bot
- VirusTotal API v3

## Setup (Windows / VS Code)
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
