"""Server-side runtime credential storage for authenticated CTI connectors.

Secrets are never returned to clients. The local JSON file is excluded from Git
and created with owner-only permissions so credentials can be changed without
restarting the ingestion service.
"""

import json
import os
import threading

from app.config import RUNTIME_SECRETS_PATH


PROVIDER_ENV_VARS = {
    "threatfox": "THREATFOX_AUTH_KEY",
    "urlhaus": "URLHAUS_AUTH_KEY",
}

_store_lock = threading.RLock()


def _read_store() -> dict[str, str]:
    if not RUNTIME_SECRETS_PATH.exists():
        return {}
    try:
        data = json.loads(RUNTIME_SECRETS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {str(key): str(value) for key, value in data.items() if value}


def get_provider_secret(provider: str) -> str:
    """Return a provider key from runtime storage, falling back to its env var."""
    env_name = PROVIDER_ENV_VARS.get(provider)
    if not env_name:
        raise ValueError("Unsupported credential provider")
    with _store_lock:
        value = _read_store().get(provider, "")
    return value or os.getenv(env_name, "")


def provider_secret_is_configured(provider: str) -> bool:
    return bool(get_provider_secret(provider))


def save_provider_secret(provider: str, api_key: str) -> None:
    if provider not in PROVIDER_ENV_VARS:
        raise ValueError("Unsupported credential provider")
    value = api_key.strip()
    if not value or len(value) > 512 or any(char in value for char in "\r\n\0"):
        raise ValueError("API key must contain 1 to 512 characters on one line")

    with _store_lock:
        data = _read_store()
        data[provider] = value
        RUNTIME_SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp_path = RUNTIME_SECRETS_PATH.with_name(f".{RUNTIME_SECRETS_PATH.name}.tmp")
        file_descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.chmod(temp_path, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, RUNTIME_SECRETS_PATH)
            os.chmod(RUNTIME_SECRETS_PATH, 0o600)
        finally:
            if temp_path.exists():
                temp_path.unlink()


def delete_provider_secret(provider: str) -> None:
    if provider not in PROVIDER_ENV_VARS:
        raise ValueError("Unsupported credential provider")
    with _store_lock:
        data = _read_store()
        data.pop(provider, None)
        if data:
            save_provider_secret_file(data)
        elif RUNTIME_SECRETS_PATH.exists():
            RUNTIME_SECRETS_PATH.unlink()


def save_provider_secret_file(data: dict[str, str]) -> None:
    """Rewrite an already validated store while preserving owner-only access."""
    RUNTIME_SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = RUNTIME_SECRETS_PATH.with_name(f".{RUNTIME_SECRETS_PATH.name}.tmp")
    file_descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(temp_path, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True)
            handle.write("\n")
        os.replace(temp_path, RUNTIME_SECRETS_PATH)
        os.chmod(RUNTIME_SECRETS_PATH, 0o600)
    finally:
        if temp_path.exists():
            temp_path.unlink()
