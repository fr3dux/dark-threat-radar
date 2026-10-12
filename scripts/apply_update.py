#!/usr/bin/env python3
"""Root-owned systemd update worker with validation, health check, and rollback."""

from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import os
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
FINGERPRINT_RE = re.compile(r"^[A-F0-9]{40}(?:[A-F0-9]{24})?$")
EXPECTED_REPOSITORY = "fr3dux/dark-threat-radar"
ALLOWED_ORIGINS = {
    "https://github.com/fr3dux/dark-threat-radar.git",
    "git@github.com:fr3dux/dark-threat-radar.git",
    "ssh://git@github.com/fr3dux/dark-threat-radar.git",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        parent_stat = path.parent.stat()
        os.fchown(descriptor, parent_stat.st_uid, parent_stat.st_gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def run(
    command: list[str],
    cwd: Path | None = None,
    env: dict | None = None,
    echo_output: bool = True,
    user: int | None = None,
    group: int | None = None,
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        user=user,
        group=group,
    )
    if result.stdout and echo_output:
        print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed ({command[0]} exited {result.returncode})")
    return result.stdout.strip()


def trusted_signing_fingerprint(path: Path) -> str:
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("Release signing policy must be root-owned and not writable by other users")
    fingerprint = path.read_text(encoding="ascii").strip().replace(" ", "").upper()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise RuntimeError("Release signing policy contains an invalid fingerprint")
    return fingerprint


def trusted_executable(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError("Release signature verifier must be a root-owned executable")
    if not metadata.st_mode & stat.S_IXUSR:
        raise RuntimeError("Release signature verifier is not executable")
    return resolved


def verify_release_signature(
    project_root: Path,
    tag: str,
    fingerprint: str,
    verifier: Path,
    *,
    user: int,
    group: int,
) -> None:
    verifier = trusted_executable(verifier)
    output = run(
        [
            "git",
            "-c", "gpg.format=openpgp",
            "-c", f"gpg.program={verifier}",
            "verify-tag", "--raw", tag,
        ], cwd=project_root,
        echo_output=False, user=user, group=group,
    )
    valid_fingerprints: set[str] = set()
    for line in output.splitlines():
        if "[GNUPG:] VALIDSIG " not in line:
            continue
        valid_fingerprints.update(
            field.upper()
            for field in line.split()
            if FINGERPRINT_RE.fullmatch(field.upper())
        )
    if fingerprint not in valid_fingerprints:
        raise RuntimeError("Release tag was not signed by the configured trusted key")


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"").strip("'")
    return values


def resolve_database(project_root: Path, env_values: dict[str, str]) -> Path:
    configured = env_values.get("DB_PATH", "")
    if not configured:
        return project_root / "threat_radar.db"
    path = Path(configured)
    return path if path.is_absolute() else project_root / path


def validate_service_database(
    path: Path, service_uid: int, allowed_roots: tuple[Path, ...] | None = None
) -> tuple[Path, int]:
    """Prevent the root worker from following an application-planted symlink."""
    if path.is_symlink():
        raise RuntimeError("Database path must not be a symbolic link")
    resolved = path.resolve(strict=True)
    if allowed_roots:
        roots = tuple(root.resolve() for root in allowed_roots)
        if not any(resolved == root or root in resolved.parents for root in roots):
            raise RuntimeError("Database path is outside the permitted application data roots")
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != service_uid:
        raise RuntimeError("Database must be a regular file owned by the application service")
    return resolved, stat.S_IMODE(metadata.st_mode)


def read_update_request(path: Path, max_bytes: int = 16 * 1024) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise RuntimeError("Update request is not a valid bounded regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            payload = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise RuntimeError("Update request must be a JSON object")
    return payload


def backup_database(source: Path, destination: Path) -> bool:
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as backup_db:
        source_db.backup(backup_db)
    os.chmod(destination, 0o600)
    return True


def relocate_virtualenv(venv_path: Path, previous_path: Path) -> None:
    """Repair text launchers after an atomic virtualenv directory move.

    Python virtual environments are not relocatable by default: console-script
    shebangs and activation helpers contain the absolute path used at creation
    time. The updater builds in an isolated temporary directory, so those paths
    must be rewritten immediately after the validated environment is activated.
    """
    old_prefix = str(previous_path).encode("utf-8")
    new_prefix = str(venv_path).encode("utf-8")
    bin_path = venv_path / "bin"
    if not bin_path.is_dir():
        raise RuntimeError("Activated virtual environment is missing its bin directory")

    for entry in bin_path.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        content = entry.read_bytes()
        if b"\x00" in content or old_prefix not in content:
            continue
        entry.write_bytes(content.replace(old_prefix, new_prefix))


def wait_for_health(port: str, expected_version: str, attempts: int = 20) -> bool:
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return False
    if not 1 <= port_number <= 65535:
        return False
    for _ in range(attempts):
        connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=3)
        try:
            connection.request("GET", "/api/version")
            response = connection.getresponse()
            payload = json.loads(response.read())
            if response.status == 200 and payload.get("version") == expected_version:
                return True
        except Exception:
            pass
        finally:
            connection.close()
        time.sleep(2)
    return False


def remove_worktree(
    project_root: Path, worktree: Path, *, user: int | None = None, group: int | None = None
) -> None:
    if worktree.exists():
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=project_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            user=user,
            group=group,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply a validated Dark Threat Radar update")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--service", default="threat-radar.service")
    parser.add_argument("--service-user", required=True)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/dark-threat-radar"))
    parser.add_argument("--trusted-signing-fingerprint-file", type=Path, required=True)
    parser.add_argument("--signature-verifier", type=Path, required=True)
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    state_dir = args.state_dir.resolve()
    app_state_dir = state_dir / "app"
    request_path = app_state_dir / "update.request.json"
    status_path = app_state_dir / "update-status.json"
    lock_path = state_dir / "update.lock"
    state_dir.mkdir(parents=True, exist_ok=True)
    account = pwd.getpwnam(args.service_user)
    if account.pw_uid == 0:
        raise RuntimeError("Refusing to run release code as root")
    signing_fingerprint = trusted_signing_fingerprint(
        args.trusted_signing_fingerprint_file.resolve()
    )
    signature_verifier = trusted_executable(args.signature_verifier)
    run_uid = account.pw_uid
    run_gid = account.pw_gid

    with lock_path.open("w", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0

        previous_commit = ""
        previous_version = ""
        target_version = ""
        database_path: Path | None = None
        database_backup: Path | None = None
        database_mode: int | None = None
        database_backed_up = False
        old_venv: Path | None = None
        new_venv: Path | None = None
        service_stopped = False
        worktree = project_root / f".update-worktree-{os.getpid()}"
        request: dict = {}

        try:
            request = read_update_request(request_path)
            request_path.unlink(missing_ok=True)
            target_tag = str(request.get("target_tag", ""))
            repository = str(request.get("repository", ""))
            match = SEMVER_RE.fullmatch(target_tag)
            if repository != EXPECTED_REPOSITORY or not match:
                raise RuntimeError("Update request did not match the official stable release channel")
            target_version = ".".join(match.groups())

            atomic_json(status_path, {
                "state": "validating", "message": "Validating official release and local installation",
                "target_version": target_version, "started_at": utc_now(), "progress": 10,
            })

            origin = run(["git", "remote", "get-url", "origin"], cwd=project_root, echo_output=False, user=run_uid, group=run_gid)
            if origin not in ALLOWED_ORIGINS:
                raise RuntimeError("Git origin is not the official Dark Threat Radar repository")
            if run(["git", "branch", "--show-current"], cwd=project_root, user=run_uid, group=run_gid) != "main":
                raise RuntimeError("Automatic updates require the main branch")
            if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=project_root, user=run_uid, group=run_gid):
                raise RuntimeError("Local changes or untracked files must be removed before updating")

            previous_commit = run(["git", "rev-parse", "HEAD"], cwd=project_root, user=run_uid, group=run_gid)
            previous_version = run(
                [sys.executable, "-c", "from app.version import __version__; print(__version__)"],
                cwd=project_root,
                user=run_uid, group=run_gid,
            )
            run(["git", "fetch", "origin", "main:refs/remotes/origin/main"], cwd=project_root, user=run_uid, group=run_gid)
            run(["git", "fetch", "origin", f"refs/tags/{target_tag}:refs/tags/{target_tag}"], cwd=project_root, user=run_uid, group=run_gid)
            if run(["git", "cat-file", "-t", f"refs/tags/{target_tag}"], cwd=project_root, user=run_uid, group=run_gid) != "tag":
                raise RuntimeError("The target must be an annotated official release tag")
            verify_release_signature(
                project_root, target_tag, signing_fingerprint, signature_verifier,
                user=run_uid, group=run_gid,
            )
            target_commit = run(["git", "rev-parse", f"refs/tags/{target_tag}^{{commit}}"], cwd=project_root, user=run_uid, group=run_gid)
            run(["git", "merge-base", "--is-ancestor", previous_commit, target_commit], cwd=project_root, user=run_uid, group=run_gid)
            run(["git", "merge-base", "--is-ancestor", target_commit, "refs/remotes/origin/main"], cwd=project_root, user=run_uid, group=run_gid)

            atomic_json(status_path, {
                "state": "testing", "message": "Building an isolated environment and running validation",
                "target_version": target_version, "previous_version": previous_version,
                "started_at": utc_now(), "progress": 30,
            })
            remove_worktree(project_root, worktree, user=run_uid, group=run_gid)
            run(["git", "worktree", "add", "--detach", str(worktree), target_commit], cwd=project_root, user=run_uid, group=run_gid)
            new_venv = project_root / f".update-venv-{os.getpid()}"
            if new_venv.exists():
                shutil.rmtree(new_venv)
            run([sys.executable, "-m", "venv", str(new_venv)], user=run_uid, group=run_gid)
            update_python = new_venv / "bin" / "python"
            run([str(update_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"], user=run_uid, group=run_gid)
            run([
                str(update_python), "-m", "pip", "install", "--quiet", "--require-hashes",
                "-r", str(worktree / "requirements-dev.lock"),
            ], user=run_uid, group=run_gid)
            test_env = os.environ.copy()
            for secret_name in (
                "THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "MB_API_KEY",
                "NVD_API_KEY", "GITHUB_TOKEN", "OTX_API_KEY",
                "PHISHTANK_API_KEY", "ABUSEIPDB_API_KEY",
            ):
                test_env.pop(secret_name, None)
            test_env.update({
                "BASE_DIR": str(worktree),
                "DB_PATH": str(app_state_dir / f"test-{os.getpid()}.db"),
                "RUNTIME_SECRETS_PATH": str(app_state_dir / f"test-secrets-{os.getpid()}.json"),
                "LOCAL_NEWS_FILE": str(app_state_dir / "no-local-news.json"),
                "SETTINGS_ADMIN_TOKEN": "update-validation-only-0123456789abcdef",
                "ENABLE_WEB_UPDATES": "false",
                "ENABLE_OPENPHISH": "false",
                "PYTHONPATH": str(worktree),
            })
            test_env["HOME"] = account.pw_dir
            run([str(update_python), "-m", "pytest", "-q", str(worktree / "tests")], cwd=worktree, env=test_env, user=run_uid, group=run_gid)
            if shutil.which("node"):
                run(["node", "--check", str(worktree / "app" / "static" / "js" / "app.js")], user=run_uid, group=run_gid)
            run([str(update_python), "-m", "pip", "uninstall", "--yes", "pytest", "setuptools", "wheel"], user=run_uid, group=run_gid)
            run([str(update_python), "-m", "pip", "uninstall", "--yes", "pip"], user=run_uid, group=run_gid)

            env_values = load_env_file(project_root / ".env")
            database_path, database_mode = validate_service_database(
                resolve_database(project_root, env_values), run_uid,
                allowed_roots=(project_root, app_state_dir),
            )
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            database_backup = state_dir / "backups" / f"threat-radar-{previous_version}-{stamp}.db"
            database_backed_up = backup_database(database_path, database_backup)
            run(["git", "branch", f"backup/auto-{stamp}-{previous_commit[:7]}", previous_commit], cwd=project_root, user=run_uid, group=run_gid)

            atomic_json(status_path, {
                "state": "installing", "message": "Activating the validated release",
                "target_version": target_version, "previous_version": previous_version,
                "started_at": utc_now(), "progress": 70,
            })
            run(["systemctl", "stop", args.service])
            service_stopped = True
            run(["git", "merge", "--ff-only", target_commit], cwd=project_root, user=run_uid, group=run_gid)

            current_venv = project_root / "venv"
            old_venv = project_root / f".venv-backup-{os.getpid()}"
            if old_venv.exists():
                shutil.rmtree(old_venv)
            os.replace(current_venv, old_venv)
            staged_venv = new_venv
            os.replace(staged_venv, current_venv)
            relocate_virtualenv(current_venv, staged_venv)
            new_venv = None
            run(["systemctl", "start", args.service])
            service_stopped = False

            if not wait_for_health(env_values.get("PORT", "9220"), target_version):
                raise RuntimeError("The updated service failed its health check")

            atomic_json(status_path, {
                "state": "succeeded", "message": "Update installed successfully",
                "target_version": target_version, "previous_version": previous_version,
                "started_at": utc_now(), "finished_at": utc_now(), "progress": 100,
                "rolled_back": False,
            })
            if old_venv and old_venv.exists():
                try:
                    shutil.rmtree(old_venv)
                except OSError as cleanup_error:
                    print(f"Old environment cleanup deferred: {cleanup_error}", flush=True)
            remove_worktree(project_root, worktree, user=run_uid, group=run_gid)
            return 0

        except Exception as exc:
            print(f"Update failed: {exc}", file=sys.stderr, flush=True)
            rolled_back = False
            if (previous_commit and service_stopped) or (
                previous_commit and old_venv and old_venv.exists()
            ):
                try:
                    subprocess.run(["systemctl", "stop", args.service], check=False)
                    run(["git", "reset", "--hard", previous_commit], cwd=project_root, user=run_uid, group=run_gid)
                    current_venv = project_root / "venv"
                    if old_venv and old_venv.exists():
                        failed_venv = project_root / f".failed-venv-{os.getpid()}"
                        if current_venv.exists():
                            os.replace(current_venv, failed_venv)
                        os.replace(old_venv, current_venv)
                        if failed_venv.exists():
                            shutil.rmtree(failed_venv)
                    if database_backed_up and database_path and database_backup:
                        current_metadata = database_path.lstat()
                        if (
                            not stat.S_ISREG(current_metadata.st_mode)
                            or current_metadata.st_uid != run_uid
                        ):
                            raise RuntimeError("Refusing to restore database through an unsafe path")
                        Path(f"{database_path}-wal").unlink(missing_ok=True)
                        Path(f"{database_path}-shm").unlink(missing_ok=True)
                        shutil.copy2(database_backup, database_path)
                        os.chown(database_path, run_uid, run_gid)
                        os.chmod(database_path, database_mode or 0o600)
                    run(["systemctl", "start", args.service])
                    rolled_back = True
                except Exception as rollback_exc:
                    print(f"Rollback failed: {rollback_exc}", file=sys.stderr, flush=True)

            atomic_json(status_path, {
                "state": "rolled_back" if rolled_back else "failed",
                "message": "Update failed and the previous version was restored" if rolled_back else str(exc),
                "target_version": target_version or request.get("target_version"),
                "previous_version": previous_version or None,
                "started_at": utc_now(), "finished_at": utc_now(), "progress": 100,
                "rolled_back": rolled_back,
            })
            remove_worktree(project_root, worktree, user=run_uid, group=run_gid)
            if new_venv and new_venv.exists():
                shutil.rmtree(new_venv)
            return 1
        finally:
            request_path.unlink(missing_ok=True)
            for test_file in app_state_dir.glob(f"test-{os.getpid()}.db*"):
                test_file.unlink(missing_ok=True)
            (app_state_dir / f"test-secrets-{os.getpid()}.json").unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
