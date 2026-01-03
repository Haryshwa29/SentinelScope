import os
import requests
import base64
import logging
import time
import uuid


from dotenv import load_dotenv
from difflib import get_close_matches
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.ext import MessageHandler, filters
from telegram import InlineQueryResultArticle, InputTextMessageContent
from telegram.ext import InlineQueryHandler
from telegram import User

async def inline_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.inline_query:
        return

    q = update.inline_query.query.strip()
    if not q:
        return

    # Normalize
    if not q.startswith(("http://", "https://")):
        q = "https://" + q

    # Quick sanity
    if "." not in q:
        return

    # Basic response (you can plug VT logic here)
    text = f"✅ Ready to scan:\n{q}\n\nTip: Use /scan_url in DM for full report."

    result = InlineQueryResultArticle(
        id=str(uuid.uuid4()),
        title=f"Scan {q}",
        input_message_content=InputTextMessageContent(text),
        description="Tap to insert result",
    )

    await update.inline_query.answer([result], cache_time=5)

def get_user_id(update: Update) -> int | None:
    user: User | None = update.effective_user
    if user:
        return user.id
    # Fallback if effective_user is missing
    msg = update.message
    if msg and msg.from_user:
        return msg.from_user.id
    return None


RATE_LIMIT = {}
WINDOW = 30   # seconds
MAX_REQ = 5

def is_rate_limited(user_id: int) -> bool:
    now = time.time()
    timestamps = RATE_LIMIT.get(user_id, [])

    # keep only requests in the window
    timestamps = [t for t in timestamps if now - t < WINDOW]

    if len(timestamps) >= MAX_REQ:
        RATE_LIMIT[user_id] = timestamps
        return True

    timestamps.append(now)
    RATE_LIMIT[user_id] = timestamps
    return False


load_dotenv()
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

if not TOKEN:
    raise SystemExit("TELEGRAM_BOT_TOKEN not found. Check your .env file.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    log_event(update.effective_user, "start")
    if update.message:
        await update.message.reply_text(
            "🛡️ SentinelScope is online.\n\nCommands:\n/start\n/help"
        )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message:
        await update.message.reply_text(
            "Try:\n/start\n\nNext we’ll add:\n/scan_url <url>\n/scan_ip <ip>"
        )

logging.basicConfig(
    filename="bot.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

def log_event(user, action, value=""):
    logging.info(
        f"user_id={user.id if user else 'NA'} "
        f"username={user.username if user else 'NA'} "
        f"action={action} value={value}"
    )



def vt_url_id(url: str) -> str:
    # VirusTotal expects URL-safe base64 without '=' padding
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def extract_url_from_text(text: str) -> str | None:
    parts = text.strip().split()
    if len(parts) < 2:
        return None

    first = parts[0].lower()

    # Accept exact keywords + common typos via fuzzy match
    keywords = ["scan", "check", "analyze", "analyse"]
    if first not in keywords:
        close = get_close_matches(first, keywords, n=1, cutoff=0.8)
        if not close:
            return None  # not intended as scan
        # If it's a close typo, treat it as intended
        # e.g., chekc -> check, scna -> scan

    return parts[1]

async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # 1️⃣ Guard: message must exist (fixes reply_text warnings)
    if not update.message:
        return

    # 2️⃣ Get user ID safely
    user_id = get_user_id(update)

    if user_id is None:
        await update.message.reply_text("⚠️ Unable to identify user.")
        return

    # 3️⃣ Rate limiting
    if is_rate_limited(user_id):
        await update.message.reply_text("⏳ Rate limit exceeded. Try again later.")
        return

    # 4️⃣ Ensure API key exists
    if not VT_API_KEY:
        await update.message.reply_text("❌ VT_API_KEY missing on server.")
        return

    # 5️⃣ Validate input
    if not context.args:
        await update.message.reply_text("Usage: /scan_url https://example.com")
        return

    url = context.args[0].strip()

    # Auto-add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    from urllib.parse import urlparse

    parsed = urlparse(url)
    if not parsed.netloc:
        await update.message.reply_text("❌ Invalid URL format.")
        return

    # 6️⃣ Log request
    log_event(update.effective_user, "scan_url", url)

    await update.message.reply_text("🔎 Scanning URL with VirusTotal...")

    # 7️⃣ Submit URL to VirusTotal
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={"x-apikey": VT_API_KEY},
        data={"url": url},
        timeout=20,
    )

    if submit.status_code not in (200, 201):
        await update.message.reply_text(
            f"❌ VirusTotal submission failed ({submit.status_code})"
        )
        return

    # 8️⃣ Fetch URL report
    url_id = vt_url_id(url)

    report = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": VT_API_KEY},
        timeout=20,
    )

    if report.status_code != 200:
        await update.message.reply_text(
            f"❌ VirusTotal report failed ({report.status_code})"
        )
        return

    attrs = report.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    verdict = (
        "🟢 Clean-ish"
        if malicious == 0 and suspicious == 0
        else "🔴 Risky"
    )

    # 9️⃣ Final response
    await update.message.reply_text(
        f"{verdict}\n\n"
        f"URL: {url}\n"
        f"Malicious: {malicious}\n"
        f"Suspicious: {suspicious}\n"
        f"Harmless: {harmless}\n"
        f"Undetected: {undetected}"
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()
    lower = text.lower()

    # 1️⃣ Greeting handling
    greetings = ["hi", "hello", "hey", "hola", "hii"]
    if any(lower == g or lower.startswith(g + " ") for g in greetings):
        await update.message.reply_text(
            "👋 Hi! Welcome to *SentinelScope* 🛡️\n\n"
            "I can scan URLs for security threats.\n\n"
            "👉 Just type:\n"
            "`scan google.com`\n"
            "`check example.org`\n\n"
            "Or use commands:\n"
            "`/scan_url example.com`\n"
            "`/help`",
            parse_mode="Markdown"
        )
        return

    # 2️⃣ Natural-language scan trigger
    url = extract_url_from_text(text)
    if url:
        # Re-route to scan_url by injecting args
        context.args = [url]
        await scan_url(update, context)
        return
    
        # 3️⃣ Fallback: user typed something unrecognized
    await update.message.reply_text(
        "🤔 I didn’t understand that.\n\n"
        "Try one of these:\n"
        "• `scan google.com`\n"
        "• `check example.org`\n"
        "• `/scan_url example.com`\n"
        "• `/help`",
        parse_mode="Markdown"
    )


def build_telegram_app() -> Application:
    app = Application.builder().token(TOKEN).build()

    # your handlers (same as before)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("scan_url", scan_url))
    app.add_handler(InlineQueryHandler(inline_scan))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    return app


def main():
    app = build_telegram_app()


if __name__ == "__main__":
    main()
