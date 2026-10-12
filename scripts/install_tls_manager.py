#!/usr/bin/env python3
"""Install the root-owned Nginx TLS manager used by the Settings page."""

from __future__ import annotations

import argparse
import os
import pwd
import shutil
import subprocess
from pathlib import Path


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Dark Threat Radar TLS manager")
    parser.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument(
        "--app-user",
        required=True,
        help="Unprivileged user running the Threat Radar web service",
    )
    parser.add_argument("--install-nginx", action="store_true", help="Install Nginx with apt when it is missing")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run this installer as root")
    project_root = Path(args.project_root).resolve()
    daemon = project_root / "scripts/tls_manager_daemon.py"
    system_python = shutil.which("python3")
    if not daemon.is_file() or not system_python:
        raise SystemExit("System Python or TLS daemon not found")
    if shutil.which("nginx") is None:
        if not args.install_nginx:
            raise SystemExit("Nginx is missing. Re-run with --install-nginx on Debian/Ubuntu.")
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "nginx", "curl"])
    account = pwd.getpwnam(args.app_user)
    if account.pw_uid == 0:
        raise SystemExit("Refusing root as --app-user; run the web service as an unprivileged account")
    control_dir = Path("/var/lib/dark-threat-radar/tls")
    control_dir.mkdir(parents=True, exist_ok=True)
    inbox_dir = control_dir / "inbox"
    uploads_dir = inbox_dir / "uploads"
    inbox_dir.mkdir(exist_ok=True)
    uploads_dir.mkdir(exist_ok=True)
    os.chown(control_dir, 0, 0)
    os.chown(inbox_dir, account.pw_uid, account.pw_gid)
    os.chown(uploads_dir, account.pw_uid, account.pw_gid)
    # The unprivileged service needs traversal to its private inbox/ child only;
    # listing and writes remain denied at this root-owned boundary.
    os.chmod(control_dir, 0o711)  # nosec B103
    os.chmod(inbox_dir, 0o700)
    os.chmod(uploads_dir, 0o700)
    (control_dir / "ready").write_text("ready\n", encoding="utf-8")
    os.chown(control_dir / "ready", 0, 0)
    os.chmod(control_dir / "ready", 0o644)
    default_site = Path("/etc/nginx/sites-enabled/default")
    if default_site.exists():
        disabled_site = default_site.with_name("default.disabled-by-dark-threat-radar")
        if disabled_site.exists():
            default_site.unlink()
        else:
            default_site.rename(disabled_site)
    worker_dir = Path("/usr/local/lib/dark-threat-radar")
    worker_dir.mkdir(parents=True, exist_ok=True)
    installed_daemon = worker_dir / "tls_manager_daemon.py"
    shutil.copyfile(daemon, installed_daemon)
    os.chown(worker_dir, 0, 0)
    os.chown(installed_daemon, 0, 0)
    os.chmod(worker_dir, 0o700)
    os.chmod(installed_daemon, 0o700)
    unit = f"""[Unit]
Description=Dark Threat Radar TLS Configuration Manager
After=network.target nginx.service
Requires=nginx.service

[Service]
Type=simple
User=root
ExecStart={system_python} {installed_daemon} --control-dir {control_dir}
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
UMask=0077
ReadWritePaths={control_dir} /etc/nginx

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/dark-threat-radar-tls-manager.service").write_text(unit, encoding="utf-8")
    run(["nginx", "-t"])
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "nginx", "dark-threat-radar-tls-manager.service"])
    print("TLS manager installed. The Settings page can now activate HTTPS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
