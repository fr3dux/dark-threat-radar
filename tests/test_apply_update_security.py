"""Security boundary tests for the root-owned native update worker."""

import json
import os
import stat
from types import SimpleNamespace

import pytest

from scripts import apply_update, install_systemd_updater


def test_update_request_rejects_symlink(tmp_path):
    real_request = tmp_path / "real.json"
    real_request.write_text(json.dumps({"target_tag": "v1.2.3"}), encoding="utf-8")
    linked_request = tmp_path / "request.json"
    linked_request.symlink_to(real_request)

    with pytest.raises(OSError):
        apply_update.read_update_request(linked_request)


def test_update_request_is_bounded_and_requires_object(tmp_path):
    request = tmp_path / "request.json"
    request.write_text("[]", encoding="utf-8")
    with pytest.raises(RuntimeError, match="JSON object"):
        apply_update.read_update_request(request)

    request.write_bytes(b"x" * (16 * 1024 + 1))
    with pytest.raises(RuntimeError, match="bounded regular file"):
        apply_update.read_update_request(request)


def test_database_must_be_regular_owned_file(tmp_path):
    database = tmp_path / "threat-radar.db"
    database.write_bytes(b"sqlite")
    resolved, mode = apply_update.validate_service_database(database, os.getuid())
    assert resolved == database.resolve()
    assert mode & 0o600 == 0o600

    linked = tmp_path / "linked.db"
    linked.symlink_to(database)
    with pytest.raises(RuntimeError, match="symbolic link"):
        apply_update.validate_service_database(linked, os.getuid())

    outside_root = tmp_path / "allowed"
    outside_root.mkdir()
    with pytest.raises(RuntimeError, match="permitted application data roots"):
        apply_update.validate_service_database(
            database, os.getuid(), allowed_roots=(outside_root,)
        )


def test_release_signature_requires_exact_configured_fingerprint(tmp_path, monkeypatch):
    trusted = "A" * 40
    verifier = tmp_path / "verify-release"
    verifier.write_text("#!/bin/sh\n", encoding="utf-8")
    verifier.chmod(0o700)
    monkeypatch.setattr(
        apply_update,
        "trusted_executable", lambda path: path,
    )
    monkeypatch.setattr(
        apply_update, "run",
        lambda *_args, **_kwargs: (
            f"[GNUPG:] VALIDSIG {'C' * 40} 2026-10-12 0 4 0 1 10 00 {trusted}"
        ),
    )
    apply_update.verify_release_signature(
        tmp_path, "v1.2.3", trusted, verifier, user=1000, group=1000
    )

    with pytest.raises(RuntimeError, match="trusted key"):
        apply_update.verify_release_signature(
            tmp_path, "v1.2.3", "B" * 40, verifier, user=1000, group=1000
        )


def test_signature_verifier_must_be_root_owned_and_protected(tmp_path, monkeypatch):
    class UnsafeVerifier:
        def resolve(self, strict):
            assert strict is True
            return self

        def stat(self):
            return SimpleNamespace(
                st_mode=stat.S_IFREG | stat.S_IXUSR | stat.S_IWGRP,
                st_uid=0,
            )

    with pytest.raises(RuntimeError, match="root-owned executable"):
        apply_update.trusted_executable(UnsafeVerifier())


def test_bundled_public_key_must_match_official_fingerprint(tmp_path, monkeypatch):
    public_key = tmp_path / "release.asc"
    public_key.write_text(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n",
        encoding="ascii",
    )
    listing = (
        "pub:u:255:22:906B0522A372818E:0:0::u:::scSC:::::ed25519:::0:\n"
        f"fpr:::::::::{install_systemd_updater.OFFICIAL_SIGNING_FINGERPRINT}:\n"
        "uid:u::::::::Dark Threat Radar Releases:\n"
    )
    monkeypatch.setattr(install_systemd_updater, "run", lambda _command: listing)

    assert install_systemd_updater.bundled_public_key_fingerprint(
        public_key, tmp_path / "gpg"
    ) == install_systemd_updater.OFFICIAL_SIGNING_FINGERPRINT


def test_bundled_release_key_rejects_private_key_material(tmp_path):
    private_key = tmp_path / "release.asc"
    private_key.write_text(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n"
        "-----END PGP PRIVATE KEY BLOCK-----\n",
        encoding="ascii",
    )
    with pytest.raises(RuntimeError, match="Only the official public"):
        install_systemd_updater.bundled_public_key_fingerprint(
            private_key, tmp_path / "gpg"
        )


def test_updater_installer_refuses_symlinked_environment_file(tmp_path):
    target = tmp_path / "unrelated"
    target.write_text("preserve=true\n", encoding="utf-8")
    env_link = tmp_path / ".env"
    env_link.symlink_to(target)

    with pytest.raises(OSError):
        install_systemd_updater.set_env_values(
            env_link, {"ENABLE_WEB_UPDATES": "true"}, {0, os.getuid()}
        )
    assert target.read_text(encoding="utf-8") == "preserve=true\n"
