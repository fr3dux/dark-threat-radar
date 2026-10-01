"""Tests for per-installation administrative access setup."""

import re
import stat

from scripts.setup_admin import setup_environment


def test_setup_environment_generates_and_preserves_unique_code(tmp_path):
    (tmp_path / ".env.example").write_text(
        "HOST=0.0.0.0\nSETTINGS_ADMIN_TOKEN=\nPORT=9220\n",
        encoding="utf-8",
    )

    token, generated = setup_environment(tmp_path)

    assert generated is True
    assert re.fullmatch(r"[0-9a-f]{48}", token)
    assert f"SETTINGS_ADMIN_TOKEN={token}" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600

    existing_token, generated_again = setup_environment(tmp_path)

    assert generated_again is False
    assert existing_token == token
