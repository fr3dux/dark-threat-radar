#!/usr/bin/env python3
"""Install the privilege-separated systemd updater for a native deployment."""

import argparse
import os
import pwd
import re
import shutil
import subprocess
from pathlib import Path


def run(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"{command[0]} failed")
    return result.stdout.strip()


def set_env_values(path: Path, values: dict[str, str]) -> None:
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    for key, value in values.items():
        pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
        line = f"{key}={value}"
        if pattern.search(content):
            content = pattern.sub(line, content)
        else:
            if content and not content.endswith("\n"):
                content += "\n"
            content += line + "\n"
    temp = path.with_name(".env.updater.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Dark Threat Radar web updater")
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--service", default="threat-radar.service")
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/dark-threat-radar"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run this installer as root (sudo).")

    project_root = args.project_root.resolve()
    state_dir = args.state_dir.resolve()
    source_helper = Path(__file__).resolve().with_name("apply_update.py")
    if not (project_root / ".git").exists() or not source_helper.is_file():
        raise SystemExit(f"Invalid Dark Threat Radar checkout: {project_root}")

    system_python_text = shutil.which("python3")
    if not system_python_text:
        raise SystemExit("A system Python 3 interpreter is required.")
    system_python = Path(system_python_text).resolve()
    python_stat = system_python.stat()
    if project_root in system_python.parents or python_stat.st_uid != 0 or python_stat.st_mode & 0o022:
        raise SystemExit("The updater requires a root-owned, non-writable system Python interpreter.")

    service_user = run(["systemctl", "show", args.service, "--property=User", "--value"]) or "root"
    try:
        account = pwd.getpwnam(service_user)
    except KeyError as exc:
        raise SystemExit(f"Service user does not exist: {service_user}") from exc

    state_dir.mkdir(parents=True, exist_ok=True)
    os.chown(state_dir, account.pw_uid, account.pw_gid)
    os.chmod(state_dir, 0o750)
    ready_path = state_dir / "updater.ready"
    ready_path.write_text("systemd-v1\n", encoding="utf-8")
    os.chown(ready_path, account.pw_uid, account.pw_gid)
    os.chmod(ready_path, 0o640)

    helper_dir = Path("/usr/local/lib/dark-threat-radar")
    helper_dir.mkdir(parents=True, exist_ok=True)
    installed_helper = helper_dir / "apply_update.py"
    shutil.copy2(source_helper, installed_helper)
    os.chown(helper_dir, 0, 0)
    os.chown(installed_helper, 0, 0)
    os.chmod(helper_dir, 0o755)
    os.chmod(installed_helper, 0o755)

    update_service = f"""[Unit]
Description=Dark Threat Radar validated update worker
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory={project_root}
ExecStart={system_python} {installed_helper} --project-root {project_root} --service {args.service} --state-dir {state_dir}
TimeoutStartSec=30min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths={project_root} {state_dir}
"""
    update_path = f"""[Unit]
Description=Watch for authenticated Dark Threat Radar update requests

[Path]
PathExists={state_dir}/update.request.json
Unit=dark-threat-radar-update.service

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/dark-threat-radar-update.service").write_text(update_service, encoding="utf-8")
    Path("/etc/systemd/system/dark-threat-radar-update.path").write_text(update_path, encoding="utf-8")
    set_env_values(project_root / ".env", {
        "ENABLE_WEB_UPDATES": "true",
        "UPDATE_REPOSITORY": "fr3dux/dark-threat-radar",
        "UPDATE_REQUEST_PATH": str(state_dir / "update.request.json"),
        "UPDATE_STATUS_PATH": str(state_dir / "update-status.json"),
        "UPDATE_READY_PATH": str(ready_path),
    })
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "dark-threat-radar-update.path"])
    run(["systemctl", "restart", args.service])
    print("Dark Threat Radar one-click updater installed and enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
