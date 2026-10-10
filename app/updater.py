"""Read-only release discovery and privilege-separated update requests."""

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx

from app.config import (
    ENABLE_WEB_UPDATES,
    GITHUB_TOKEN,
    UPDATE_CHECK_INTERVAL_SECONDS,
    UPDATE_READY_PATH,
    UPDATE_REPOSITORY,
    UPDATE_REQUEST_PATH,
    UPDATE_STATUS_PATH,
)
from app.version import __version__


SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
ALLOWED_STATUS_FIELDS = {
    "state", "message", "target_version", "previous_version", "started_at",
    "finished_at", "progress", "rolled_back",
}
_cache: dict[str, Any] = {
    "checked_at": 0.0,
    "release": None,
    "error": None,
    "warning": None,
}
_cache_lock = asyncio.Lock()


def parse_version(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch((value or "").strip())
    if not match:
        raise ValueError("Invalid stable semantic version")
    return tuple(int(part) for part in match.groups())


def normalize_version(value: str) -> str:
    major, minor, patch = parse_version(value)
    return f"{major}.{minor}.{patch}"


def _read_update_state() -> dict[str, Any]:
    try:
        payload = json.loads(UPDATE_STATUS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {"state": "idle", "message": "No update has been requested"}
    if not isinstance(payload, dict):
        return {"state": "idle", "message": "No update has been requested"}
    return {key: payload[key] for key in ALLOWED_STATUS_FIELDS if key in payload}


def _atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


async def _fetch_latest_release() -> dict[str, Any]:
    api_base = f"https://api.github.com/repos/{UPDATE_REPOSITORY}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"DarkThreatRadar/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers=headers) as client:
        release_response = await client.get(f"{api_base}/releases/latest")
        if release_response.status_code in {403, 429}:
            return await _fetch_latest_release_from_web(client)
        release_data = None
        if release_response.status_code == 200:
            release = release_response.json()
            tag = release.get("tag_name", "")
            try:
                version = normalize_version(tag)
                release_data = {
                    "version": version,
                    "tag": f"v{version}",
                    "name": release.get("name") or f"Dark Threat Radar v{version}",
                    "url": release.get("html_url") or f"https://github.com/{UPDATE_REPOSITORY}/releases/tag/v{version}",
                    "published_at": release.get("published_at"),
                    "changelog": (release.get("body") or "").strip()[:12000],
                }
            except ValueError:
                release_data = None

        # A current or newer stable Release is authoritative. Avoid spending a
        # second unauthenticated GitHub API request on every page refresh.
        if release_data and parse_version(release_data["version"]) >= parse_version(__version__):
            return release_data

        # Tags remain a fallback for installations whose latest authored
        # Release is older than the running version.
        tags_response = await client.get(f"{api_base}/tags", params={"per_page": 30})
        if tags_response.status_code in {403, 429}:
            return await _fetch_latest_release_from_web(client)
        tags_response.raise_for_status()
        versions = []
        for item in tags_response.json():
            try:
                versions.append((parse_version(item.get("name", "")), item.get("name", "")))
            except ValueError:
                continue
        if not versions and not release_data:
            raise RuntimeError("No stable release tags were found")
        if release_data:
            versions.append((parse_version(release_data["version"]), release_data["tag"]))
        version_tuple, tag = max(versions)
        version = ".".join(str(part) for part in version_tuple)
        if release_data and parse_version(release_data["version"]) == version_tuple:
            return release_data
        return {
            "version": version,
            "tag": f"v{version}",
            "name": f"Dark Threat Radar v{version}",
            "url": f"https://github.com/{UPDATE_REPOSITORY}/releases/tag/v{version}",
            "published_at": None,
            "changelog": "Release notes are available in CHANGELOG.md.",
        }


async def _fetch_latest_release_from_web(client: httpx.AsyncClient) -> dict[str, Any]:
    """Resolve GitHub's public latest-release redirect without using REST quota."""
    response = await client.get(f"https://github.com/{UPDATE_REPOSITORY}/releases/latest")
    response.raise_for_status()
    match = re.search(r"/releases/tag/(v?\d+\.\d+\.\d+)$", str(response.url).rstrip("/"))
    if not match:
        raise RuntimeError("GitHub did not return a stable latest-release tag")
    version = normalize_version(match.group(1))
    return {
        "version": version,
        "tag": f"v{version}",
        "name": f"Dark Threat Radar v{version}",
        "url": f"https://github.com/{UPDATE_REPOSITORY}/releases/tag/v{version}",
        "published_at": None,
        "changelog": "Release notes are available on GitHub.",
    }


async def get_update_status(force: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    async with _cache_lock:
        if force or not _cache["release"] or now - _cache["checked_at"] >= UPDATE_CHECK_INTERVAL_SECONDS:
            try:
                _cache["release"] = await _fetch_latest_release()
                _cache["error"] = None
                _cache["warning"] = None
            except Exception as exc:
                message = f"Release check temporarily unavailable: {exc}"
                if _cache["release"]:
                    _cache["error"] = None
                    _cache["warning"] = message
                else:
                    _cache["error"] = message
                    _cache["warning"] = None
            _cache["checked_at"] = now

        release = _cache["release"]
        current_tuple = parse_version(__version__)
        latest_tuple = parse_version(release["version"]) if release else current_tuple
        updater_ready = ENABLE_WEB_UPDATES and UPDATE_READY_PATH.is_file()
        result = {
            "current_version": __version__,
            "latest_version": release["version"] if release else __version__,
            "latest_tag": release["tag"] if release else f"v{__version__}",
            "update_available": latest_tuple > current_tuple,
            "release_url": release["url"] if release else f"https://github.com/{UPDATE_REPOSITORY}/releases",
            "release_name": release["name"] if release else None,
            "published_at": release["published_at"] if release else None,
            "changelog": release["changelog"] if release else "",
            "check_error": _cache["error"],
            "check_warning": _cache.get("warning"),
            "updater_enabled": updater_ready,
        }
        result.update({f"update_{key}": value for key, value in _read_update_state().items()})
        return result


async def queue_latest_update() -> dict[str, Any]:
    status = await get_update_status(force=True)
    if not ENABLE_WEB_UPDATES or not UPDATE_READY_PATH.is_file():
        raise RuntimeError("One-click updates are not installed on this host")
    if status.get("check_error"):
        raise RuntimeError(status["check_error"])
    if not status["update_available"]:
        raise ValueError("This installation is already up to date")
    if UPDATE_REQUEST_PATH.exists():
        raise FileExistsError("An update request is already queued")

    request = {
        "target_version": status["latest_version"],
        "target_tag": status["latest_tag"],
        "repository": UPDATE_REPOSITORY,
        "requested_at": int(time.time()),
    }
    _atomic_json(UPDATE_STATUS_PATH, {
        "state": "queued",
        "message": "Authenticated update request queued",
        "target_version": status["latest_version"],
        "started_at": int(time.time()),
        "progress": 5,
    }, mode=0o640)
    _atomic_json(UPDATE_REQUEST_PATH, request)
    return {"status": "queued", "target_version": status["latest_version"]}
