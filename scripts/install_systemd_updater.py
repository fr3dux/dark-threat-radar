#!/usr/bin/env python3
"""Install the privilege-separated systemd updater for a native deployment."""

import argparse
import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


FINGERPRINT_RE = re.compile(r"^[A-F0-9]{40}(?:[A-F0-9]{24})?$")
OFFICIAL_SIGNING_FINGERPRINT = "2A9B25F35897A167B69F76A1906B0522A372818E"


def run(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"{command[0]} failed")
    return result.stdout.strip()


def bundled_public_key_fingerprint(path: Path, gpg: Path) -> str:
    if path.is_symlink():
        raise RuntimeError("Release signing key must not be a symbolic link")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
        raise RuntimeError("Release signing key must be a bounded regular file")
    armor = path.read_text(encoding="ascii")
    if "PRIVATE KEY BLOCK" in armor or "PUBLIC KEY BLOCK" not in armor:
        raise RuntimeError("Only the official public release signing key is accepted")

    listing = run([str(gpg), "--batch", "--show-keys", "--with-colons", str(path)])
    public_keys = 0
    primary_fingerprint = ""
    waiting_for_primary_fingerprint = False
    for line in listing.splitlines():
        fields = line.split(":")
        record_type = fields[0] if fields else ""
        if record_type == "pub":
            public_keys += 1
            waiting_for_primary_fingerprint = True
        elif record_type == "fpr" and waiting_for_primary_fingerprint:
            primary_fingerprint = fields[9].upper()
            waiting_for_primary_fingerprint = False
    if public_keys != 1 or primary_fingerprint != OFFICIAL_SIGNING_FINGERPRINT:
        raise RuntimeError("Bundled release signing key does not match the official fingerprint")
    return primary_fingerprint


def trusted_system_binary(name: str) -> Path:
    candidate = shutil.which(name)
    if not candidate:
        raise RuntimeError(f"Required system executable was not found: {name}")
    resolved = Path(candidate).resolve()
    metadata = resolved.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError(f"System executable is not root-owned and protected: {name}")
    return resolved


def set_env_values(path: Path, values: dict[str, str], allowed_uids: set[int]) -> None:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in allowed_uids:
        os.close(descriptor)
        raise RuntimeError("Environment file must be a regular file owned by root or the service user")
    with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
        content = handle.read()
        for key, value in values.items():
            pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
            line = f"{key}={value}"
            if pattern.search(content):
                content = pattern.sub(line, content)
            else:
                if content and not content.endswith("\n"):
                    content += "\n"
                content += line + "\n"
        handle.seek(0)
        handle.truncate()
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o600)


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
    source_public_key = project_root / "security" / "release-signing-key.asc"
    if not (project_root / ".git").exists() or not source_helper.is_file():
        raise SystemExit(f"Invalid Dark Threat Radar checkout: {project_root}")

    try:
        system_gpg = trusted_system_binary("gpg")
        system_gpgv = trusted_system_binary("gpgv")
        signing_fingerprint = bundled_public_key_fingerprint(source_public_key, system_gpg)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise SystemExit(str(exc)) from exc

    system_python_text = shutil.which("python3")
    if not system_python_text:
        raise SystemExit("A system Python 3 interpreter is required.")
    system_python = Path(system_python_text).resolve()
    python_stat = system_python.stat()
    if project_root in system_python.parents or python_stat.st_uid != 0 or python_stat.st_mode & 0o022:
        raise SystemExit("The updater requires a root-owned, non-writable system Python interpreter.")
    version_text = run([
        str(system_python), "-c",
        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
    ])
    try:
        system_python_version = tuple(int(part) for part in version_text.split(".", 1))
    except ValueError as exc:
        raise SystemExit("Could not determine the system Python version.") from exc
    if system_python_version < (3, 12):
        raise SystemExit("The updater requires system Python 3.12 or newer.")

    service_user = run(["systemctl", "show", args.service, "--property=User", "--value"]) or "root"
    try:
        account = pwd.getpwnam(service_user)
    except KeyError as exc:
        raise SystemExit(f"Service user does not exist: {service_user}") from exc
    if account.pw_uid == 0:
        raise SystemExit("Refusing to install updates for an application service running as root.")

    state_dir.mkdir(parents=True, exist_ok=True)
    app_state_dir = state_dir / "app"
    app_state_dir.mkdir(exist_ok=True)
    os.chown(state_dir, 0, 0)
    # The unprivileged service needs traversal to its private app/ child only;
    # listing and writes remain denied at this root-owned boundary.
    os.chmod(state_dir, 0o711)  # nosec B103
    os.chown(app_state_dir, account.pw_uid, account.pw_gid)
    os.chmod(app_state_dir, 0o700)
    ready_path = state_dir / "updater.ready"
    ready_path.write_text("systemd-v1\n", encoding="utf-8")
    os.chown(ready_path, 0, 0)
    os.chmod(ready_path, 0o644)

    trust_dir = Path("/etc/dark-threat-radar")
    trust_dir.mkdir(parents=True, exist_ok=True)
    os.chown(trust_dir, 0, 0)
    os.chmod(trust_dir, 0o755)
    fingerprint_path = trust_dir / "update-signing-fingerprint"
    fingerprint_path.write_text(signing_fingerprint + "\n", encoding="ascii")
    os.chown(fingerprint_path, 0, 0)
    os.chmod(fingerprint_path, 0o644)

    keyring_path = trust_dir / "release-signing-key.gpg"
    with tempfile.NamedTemporaryFile(prefix=".release-key-", dir=trust_dir, delete=False) as handle:
        temporary_keyring = Path(handle.name)
    try:
        run([
            str(system_gpg), "--batch", "--yes", "--dearmor",
            "--output", str(temporary_keyring), str(source_public_key),
        ])
        os.chown(temporary_keyring, 0, 0)
        os.chmod(temporary_keyring, 0o644)
        os.replace(temporary_keyring, keyring_path)
    finally:
        temporary_keyring.unlink(missing_ok=True)

    helper_dir = Path("/usr/local/lib/dark-threat-radar")
    helper_dir.mkdir(parents=True, exist_ok=True)
    installed_helper = helper_dir / "apply_update.py"
    signature_verifier = helper_dir / "verify_release_signature"
    shutil.copy2(source_helper, installed_helper)
    signature_verifier.write_text(
        "#!/bin/sh\n"
        "if [ \"$#\" -ne 5 ] || "
        "[ \"$1\" != \"--keyid-format=long\" ] || "
        "[ \"$2\" != \"--status-fd=1\" ] || "
        "[ \"$3\" != \"--verify\" ] || "
        "[ \"$5\" != \"-\" ]; then exit 2; fi\n"
        f'exec "{system_gpgv}" --keyring "{keyring_path}" "$2" "$4" "$5"\n',
        encoding="ascii",
    )
    os.chown(helper_dir, 0, 0)
    os.chown(installed_helper, 0, 0)
    os.chown(signature_verifier, 0, 0)
    os.chmod(helper_dir, 0o755)
    os.chmod(installed_helper, 0o700)
    os.chmod(signature_verifier, 0o755)

    update_service = f"""[Unit]
Description=Dark Threat Radar validated update worker
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory={project_root}
ExecStart={system_python} {installed_helper} --project-root {project_root} --service {args.service} --service-user {service_user} --state-dir {state_dir} --trusted-signing-fingerprint-file {fingerprint_path} --signature-verifier {signature_verifier}
TimeoutStartSec=30min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
UMask=0077
ReadWritePaths={project_root} {state_dir}
"""
    update_path = f"""[Unit]
Description=Watch for authenticated Dark Threat Radar update requests

[Path]
PathExists={app_state_dir}/update.request.json
Unit=dark-threat-radar-update.service

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/dark-threat-radar-update.service").write_text(update_service, encoding="utf-8")
    Path("/etc/systemd/system/dark-threat-radar-update.path").write_text(update_path, encoding="utf-8")
    set_env_values(project_root / ".env", {
        "ENABLE_WEB_UPDATES": "true",
        "UPDATE_REPOSITORY": "fr3dux/dark-threat-radar",
        "UPDATE_REQUEST_PATH": str(app_state_dir / "update.request.json"),
        "UPDATE_STATUS_PATH": str(app_state_dir / "update-status.json"),
        "UPDATE_READY_PATH": str(ready_path),
    }, {0, account.pw_uid})
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "dark-threat-radar-update.path"])
    run(["systemctl", "restart", args.service])
    print("Dark Threat Radar one-click updater installed and enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
