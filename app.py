import os
from fastapi import FastAPI, Request
from telegram import Update
from bot import build_telegram_app

telegram_app = build_telegram_app()
app = FastAPI()

@app.on_event("startup")
async def startup():
    await telegram_app.initialize()
    await telegram_app.start()
    webhook_url = os.environ["BASE_URL"] + "/webhook"
    await telegram_app.bot.set_webhook(webhook_url)

@app.on_event("shutdown")
async def shutdown():
    await telegram_app.bot.delete_webhook()
    await telegram_app.stop()
    await telegram_app.shutdown()

@app.post("/webhook")
async def telegram_webhook(request: Request):
    data = await request.json()
    update = Update.de_json(data, telegram_app.bot)
    await telegram_app.process_update(update)
    return {"ok": True}

@app.get("/")
async def health():
    return {"status": "running"}
