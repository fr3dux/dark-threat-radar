import os
from pathlib import Path

BASE_DIR = Path(os.getenv("BASE_DIR", Path(__file__).resolve().parent.parent))
DB_PATH = Path(os.getenv("DB_PATH", BASE_DIR / "threat_radar.db"))
RUNTIME_SECRETS_PATH = Path(os.getenv("RUNTIME_SECRETS_PATH", BASE_DIR / ".runtime-secrets.json"))
LOCAL_NEWS_FILE = Path(os.getenv("LOCAL_NEWS_FILE", "/root/news_history.json" if os.path.exists("/root/news_history.json") else BASE_DIR / "news_history.json"))

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "9220"))

# Sync interval in seconds (default 1 hour = 3600)
SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", "300"))

# MalwareBazaar API key if available
MB_API_KEY = os.getenv("MB_API_KEY", "")

# NIST NVD API key if available
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Optional CTI provider credentials. Secrets are server-side only.
THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY", "")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
SETTINGS_ADMIN_TOKEN = os.getenv("SETTINGS_ADMIN_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
OPENPHISH_API_KEY = os.getenv("OPENPHISH_API_KEY", "")

# The OpenPhish community feed may not be suitable for every public/commercial
# deployment. It stays disabled until the operator explicitly accepts its terms.
ENABLE_OPENPHISH = os.getenv("ENABLE_OPENPHISH", "false").lower() in {"1", "true", "yes"}

# New connectors have provider-specific schedules. Values are deliberately
# conservative and must never be configured below the provider's limits.
CTI_FAST_INTERVAL_SECONDS = max(900, int(os.getenv("CTI_FAST_INTERVAL_SECONDS", "900")))
CTI_HOURLY_INTERVAL_SECONDS = max(3600, int(os.getenv("CTI_HOURLY_INTERVAL_SECONDS", "3600")))
CTI_SLOW_INTERVAL_SECONDS = max(21600, int(os.getenv("CTI_SLOW_INTERVAL_SECONDS", "21600")))
