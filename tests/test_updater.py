"""Tests for release discovery and privilege-separated update requests."""

import asyncio
import json

import pytest
import httpx

from app import updater


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("test error", request=None, response=None)


def test_semantic_version_parser_rejects_non_stable_tags():
    assert updater.parse_version("v1.9.0") == (1, 9, 0)
    with pytest.raises(ValueError):
        updater.parse_version("v1.9.0-rc1")


def test_queue_latest_update_writes_only_validated_request(tmp_path, monkeypatch):
    ready = tmp_path / "updater.ready"
    request = tmp_path / "update.request.json"
    status_file = tmp_path / "update-status.json"
    ready.write_text("systemd-v1\n", encoding="utf-8")

    async def fake_release():
        return {
            "version": "9.9.9",
            "tag": "v9.9.9",
            "name": "Test release",
            "url": "https://github.com/fr3dux/dark-threat-radar/releases/tag/v9.9.9",
            "published_at": "2026-10-01T00:00:00Z",
            "changelog": "Validated test release",
        }

    monkeypatch.setattr(updater, "ENABLE_WEB_UPDATES", True)
    monkeypatch.setattr(updater, "UPDATE_READY_PATH", ready)
    monkeypatch.setattr(updater, "UPDATE_REQUEST_PATH", request)
    monkeypatch.setattr(updater, "UPDATE_STATUS_PATH", status_file)
    monkeypatch.setattr(updater, "_fetch_latest_release", fake_release)
    updater._cache.update({"checked_at": 0.0, "release": None, "error": None})

    result = asyncio.run(updater.queue_latest_update())
    payload = json.loads(request.read_text(encoding="utf-8"))
    operation = json.loads(status_file.read_text(encoding="utf-8"))

    assert result == {"status": "queued", "target_version": "9.9.9"}
    assert payload["repository"] == "fr3dux/dark-threat-radar"
    assert payload["target_tag"] == "v9.9.9"
    assert operation["state"] == "queued"


def test_newer_tag_wins_over_outdated_latest_release(monkeypatch):
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, params=None):
            if url.endswith("/releases/latest"):
                return FakeResponse(200, {
                    "tag_name": "v1.7.10",
                    "name": "Old latest release",
                    "html_url": "https://example.invalid/old",
                    "published_at": "2026-01-01T00:00:00Z",
                    "body": "Old notes",
                })
            return FakeResponse(200, [{"name": "v1.9.0"}, {"name": "v1.8.8"}])

    monkeypatch.setattr(updater.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    release = asyncio.run(updater._fetch_latest_release())
    assert release["version"] == "1.9.0"
    assert release["tag"] == "v1.9.0"
