import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("TELEGRAM_BOT_TOKEN", "")
print("TOKEN_LOADED =", bool(token))