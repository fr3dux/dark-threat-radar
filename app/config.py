import os
from pathlib import Path

BASE_DIR = Path(os.getenv("BASE_DIR", Path(__file__).resolve().parent.parent))
DB_PATH = Path(os.getenv("DB_PATH", BASE_DIR / "threat_radar.db"))
LOCAL_NEWS_FILE = Path(os.getenv("LOCAL_NEWS_FILE", "/root/news_history.json" if os.path.exists("/root/news_history.json") else BASE_DIR / "news_history.json"))

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "9220"))

# Sync interval in seconds (default 1 hour = 3600)
SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", "300"))

# MalwareBazaar API key if available
MB_API_KEY = os.getenv("MB_API_KEY", "")

# NIST NVD API key if available
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
