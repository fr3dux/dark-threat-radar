#!/usr/bin/env python3
"""Root-owned systemd update worker with validation, health check, and rollback."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
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
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        parent_stat = path.parent.stat()
        os.chown(path, parent_stat.st_uid, parent_stat.st_gid)
    finally:
        if temp.exists():
            temp.unlink()


def run(
    command: list[str],
    cwd: Path | None = None,
    env: dict | None = None,
    echo_output: bool = True,
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.stdout and echo_output:
        print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed ({command[0]} exited {result.returncode})")
    return result.stdout.strip()


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


def backup_database(source: Path, destination: Path) -> bool:
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as backup_db:
        source_db.backup(backup_db)
    os.chmod(destination, 0o600)
    return True


def wait_for_health(port: str, expected_version: str, attempts: int = 20) -> bool:
    url = f"http://127.0.0.1:{port}/api/version"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                payload = json.load(response)
            if response.status == 200 and payload.get("version") == expected_version:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def remove_worktree(project_root: Path, worktree: Path) -> None:
    if worktree.exists():
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=project_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply a validated Dark Threat Radar update")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--service", default="threat-radar.service")
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/dark-threat-radar"))
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    state_dir = args.state_dir.resolve()
    request_path = state_dir / "update.request.json"
    status_path = state_dir / "update-status.json"
    lock_path = state_dir / "update.lock"
    state_dir.mkdir(parents=True, exist_ok=True)

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
        database_backed_up = False
        old_venv: Path | None = None
        new_venv: Path | None = None
        service_stopped = False
        worktree = state_dir / f"worktree-{os.getpid()}"
        request: dict = {}

        try:
            request = json.loads(request_path.read_text(encoding="utf-8"))
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

            origin = run(["git", "remote", "get-url", "origin"], cwd=project_root, echo_output=False)
            if origin not in ALLOWED_ORIGINS:
                raise RuntimeError("Git origin is not the official Dark Threat Radar repository")
            if run(["git", "branch", "--show-current"], cwd=project_root) != "main":
                raise RuntimeError("Automatic updates require the main branch")
            if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=project_root):
                raise RuntimeError("Tracked local changes must be committed or reverted before updating")

            previous_commit = run(["git", "rev-parse", "HEAD"], cwd=project_root)
            previous_version = run(
                [sys.executable, "-c", "from app.version import __version__; print(__version__)"],
                cwd=project_root,
            )
            run(["git", "fetch", "origin", "main:refs/remotes/origin/main"], cwd=project_root)
            run(["git", "fetch", "origin", f"refs/tags/{target_tag}:refs/tags/{target_tag}"], cwd=project_root)
            if run(["git", "cat-file", "-t", f"refs/tags/{target_tag}"], cwd=project_root) != "tag":
                raise RuntimeError("The target must be an annotated official release tag")
            target_commit = run(["git", "rev-parse", f"refs/tags/{target_tag}^{{commit}}"], cwd=project_root)
            run(["git", "merge-base", "--is-ancestor", previous_commit, target_commit], cwd=project_root)
            run(["git", "merge-base", "--is-ancestor", target_commit, "refs/remotes/origin/main"], cwd=project_root)

            atomic_json(status_path, {
                "state": "testing", "message": "Building an isolated environment and running validation",
                "target_version": target_version, "previous_version": previous_version,
                "started_at": utc_now(), "progress": 30,
            })
            remove_worktree(project_root, worktree)
            run(["git", "worktree", "add", "--detach", str(worktree), target_commit], cwd=project_root)
            new_venv = project_root / f".update-venv-{os.getpid()}"
            if new_venv.exists():
                shutil.rmtree(new_venv)
            run([sys.executable, "-m", "venv", str(new_venv)])
            update_python = new_venv / "bin" / "python"
            run([str(update_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
            run([str(update_python), "-m", "pip", "install", "--quiet", "-r", str(worktree / "requirements.txt")])
            test_env = os.environ.copy()
            for secret_name in (
                "THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "MB_API_KEY",
                "NVD_API_KEY", "GITHUB_TOKEN", "OPENPHISH_API_KEY",
            ):
                test_env.pop(secret_name, None)
            test_env.update({
                "BASE_DIR": str(worktree),
                "DB_PATH": str(state_dir / f"test-{os.getpid()}.db"),
                "RUNTIME_SECRETS_PATH": str(state_dir / f"test-secrets-{os.getpid()}.json"),
                "LOCAL_NEWS_FILE": str(state_dir / "no-local-news.json"),
                "SETTINGS_ADMIN_TOKEN": "update-validation-only",
                "ENABLE_WEB_UPDATES": "false",
                "ENABLE_OPENPHISH": "false",
                "PYTHONPATH": str(worktree),
            })
            run([str(update_python), "-m", "pytest", "-q", str(worktree / "tests")], cwd=worktree, env=test_env)
            if shutil.which("node"):
                run(["node", "--check", str(worktree / "app" / "static" / "js" / "app.js")])

            env_values = load_env_file(project_root / ".env")
            database_path = resolve_database(project_root, env_values)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            database_backup = state_dir / "backups" / f"threat-radar-{previous_version}-{stamp}.db"
            database_backed_up = backup_database(database_path, database_backup)
            run(["git", "branch", f"backup/auto-{stamp}-{previous_commit[:7]}", previous_commit], cwd=project_root)

            atomic_json(status_path, {
                "state": "installing", "message": "Activating the validated release",
                "target_version": target_version, "previous_version": previous_version,
                "started_at": utc_now(), "progress": 70,
            })
            run(["systemctl", "stop", args.service])
            service_stopped = True
            run(["git", "merge", "--ff-only", target_commit], cwd=project_root)

            current_venv = project_root / "venv"
            old_venv = project_root / f".venv-backup-{os.getpid()}"
            if old_venv.exists():
                shutil.rmtree(old_venv)
            os.replace(current_venv, old_venv)
            os.replace(new_venv, current_venv)
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
            remove_worktree(project_root, worktree)
            return 0

        except Exception as exc:
            print(f"Update failed: {exc}", file=sys.stderr, flush=True)
            rolled_back = False
            if (previous_commit and service_stopped) or (
                previous_commit and old_venv and old_venv.exists()
            ):
                try:
                    subprocess.run(["systemctl", "stop", args.service], check=False)
                    run(["git", "reset", "--hard", previous_commit], cwd=project_root)
                    current_venv = project_root / "venv"
                    if old_venv and old_venv.exists():
                        failed_venv = project_root / f".failed-venv-{os.getpid()}"
                        if current_venv.exists():
                            os.replace(current_venv, failed_venv)
                        os.replace(old_venv, current_venv)
                        if failed_venv.exists():
                            shutil.rmtree(failed_venv)
                    if database_backed_up and database_path and database_backup:
                        Path(f"{database_path}-wal").unlink(missing_ok=True)
                        Path(f"{database_path}-shm").unlink(missing_ok=True)
                        shutil.copy2(database_backup, database_path)
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
            remove_worktree(project_root, worktree)
            if new_venv and new_venv.exists():
                shutil.rmtree(new_venv)
            return 1
        finally:
            request_path.unlink(missing_ok=True)
            for test_file in state_dir.glob(f"test-{os.getpid()}.db*"):
                test_file.unlink(missing_ok=True)
            (state_dir / f"test-secrets-{os.getpid()}.json").unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
