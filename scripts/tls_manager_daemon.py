#!/usr/bin/env python3
"""Root-owned Nginx TLS configuration worker with validation and rollback."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

FQDN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$", re.I)
REQUEST_ID_RE = re.compile(r"^[a-f0-9]{32}$")
MAX_PEM_BYTES = 32 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def atomic_json(path: Path, payload: dict) -> None:
    atomic_write(path, json.dumps(payload, indent=2, sort_keys=True))
    owner = path.parent.stat()
    os.chown(path, owner.st_uid, owner.st_gid)


def run(command: list[str]) -> None:
    subprocess.run(command, check=True, timeout=30)


def nginx_config(request: dict, cert_path: Path, key_path: Path) -> str:
    fqdn = request["fqdn"]
    http_port = int(request["http_port"])
    https_port = int(request["https_port"])
    upstream_port = int(request["upstream_port"])
    https_authority = fqdn if https_port == 443 else f"{fqdn}:{https_port}"
    if request["redirect_http"]:
        http_action = f"return 308 https://{https_authority}$request_uri;"
    else:
        http_action = f"proxy_pass http://127.0.0.1:{upstream_port};\n        include /etc/nginx/proxy_params;"
    return f"""# Managed by Dark Threat Radar. Manual edits are replaced.
server {{
    listen {http_port};
    listen [::]:{http_port};
    server_name {fqdn};
    {http_action}
}}

server {{
    listen {https_port} ssl;
    listen [::]:{https_port} ssl;
    server_name {fqdn};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:DTR_TLS:10m;
    ssl_session_timeout 1d;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {{
        proxy_pass http://127.0.0.1:{upstream_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
    }}
}}
"""


def read_untrusted_regular_file(
    path: Path, max_bytes: int = MAX_PEM_BYTES, *, directory_fd: int | None = None
) -> bytes:
    """Read an application-owned file without following its final filesystem link."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ValueError("TLS upload is not a bounded regular file")
        payload = os.read(descriptor, max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("TLS upload exceeded the safety limit")
        return payload
    finally:
        os.close(descriptor)


def read_untrusted_upload(request_dir: Path, filename: str) -> bytes:
    """Reject a symlinked upload directory as well as symlinked PEM files."""
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    directory_fd = os.open(request_dir, directory_flags)
    try:
        metadata = os.fstat(directory_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("TLS upload location is not a regular directory")
        return read_untrusted_regular_file(Path(filename), directory_fd=directory_fd)
    finally:
        os.close(directory_fd)


def read_request(path: Path, max_bytes: int = 16 * 1024) -> dict:
    payload = read_untrusted_regular_file(path, max_bytes=max_bytes)
    request = json.loads(payload.decode("utf-8"))
    if not isinstance(request, dict):
        raise ValueError("TLS request must be a JSON object")
    return request


def certificate_matches_hostname(decoded: dict, fqdn: str) -> bool:
    names = [
        value.lower().rstrip(".")
        for kind, value in decoded.get("subjectAltName", ())
        if kind == "DNS"
    ]
    if not names:
        names = [
            value.lower().rstrip(".")
            for group in decoded.get("subject", ())
            for key, value in group
            if key == "commonName"
        ]
    hostname = fqdn.lower().rstrip(".")
    return any(
        pattern == hostname
        or (
            pattern.startswith("*.")
            and hostname.endswith(pattern[1:])
            and hostname.count(".") == pattern.count(".")
        )
        for pattern in names
    )


def validate_request(request: dict, upstream_port: int) -> None:
    if not REQUEST_ID_RE.fullmatch(str(request.get("request_id", ""))):
        raise ValueError("Invalid TLS request identifier")
    if not FQDN_RE.fullmatch(str(request.get("fqdn", ""))):
        raise ValueError("Invalid TLS request hostname")
    http_port = int(request.get("http_port", 0))
    https_port = int(request.get("https_port", 0))
    if not 1 <= http_port <= 65535 or not 1 <= https_port <= 65535 or http_port == https_port:
        raise ValueError("Invalid TLS listener ports")
    if http_port in {22, upstream_port} or https_port in {22, upstream_port}:
        raise ValueError("TLS request conflicts with a protected host port")
    if int(request.get("upstream_port", 0)) != upstream_port:
        raise ValueError("Invalid internal application port")
    if not isinstance(request.get("redirect_http"), bool):
        raise ValueError("Invalid HTTP redirect policy")


def apply_request(control_dir: Path, nginx_path: Path, cert_dir: Path, request: dict) -> None:
    status_path = control_dir / "status.json"
    active_path = control_dir / "active.json"
    previous_config = nginx_path.read_text(encoding="utf-8") if nginx_path.exists() else None
    previous_cert = (cert_dir / "fullchain.pem").read_bytes() if (cert_dir / "fullchain.pem").exists() else None
    previous_key = (cert_dir / "private.key").read_bytes() if (cert_dir / "private.key").exists() else None
    status = {**request, "certificate_path": None, "private_key_path": None, "state": "applying", "configured": False, "updated_at": utc_now()}
    atomic_json(status_path, status)
    try:
        request_dir = control_dir / "inbox" / "uploads" / request["request_id"]
        certificate = read_untrusted_upload(request_dir, "fullchain.pem")
        private_key = read_untrusted_upload(request_dir, "private.key")
        cert_dir.mkdir(parents=True, exist_ok=True)
        atomic_write(cert_dir / "fullchain.pem", certificate.decode("ascii"), 0o600)
        atomic_write(cert_dir / "private.key", private_key.decode("ascii"), 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_dir / "fullchain.pem", cert_dir / "private.key")
        decoded = ssl._ssl._test_decode_cert(str(cert_dir / "fullchain.pem"))  # type: ignore[attr-defined]
        if not certificate_matches_hostname(decoded, request["fqdn"]):
            raise ValueError("Certificate does not match the requested hostname")
        atomic_write(nginx_path, nginx_config(request, cert_dir / "fullchain.pem", cert_dir / "private.key"), 0o644)
        run(["nginx", "-t"])
        run(["systemctl", "reload", "nginx"])
        https_port = int(request["https_port"])
        fqdn = request["fqdn"]
        url = f"https://{fqdn}{'' if https_port == 443 else f':{https_port}'}/api/status"
        run(["curl", "--fail", "--silent", "--show-error", "--cacert", str(cert_dir / "fullchain.pem"), "--resolve", f"{fqdn}:{https_port}:127.0.0.1", url])
        active = {
            **status,
            "state": "active", "configured": True,
            "message": "HTTPS is active", "updated_at": utc_now(),
        }
        atomic_json(active_path, active)
        atomic_json(status_path, active)
    except Exception as exc:
        if previous_config is None:
            nginx_path.unlink(missing_ok=True)
        else:
            atomic_write(nginx_path, previous_config, 0o644)
        if previous_cert is not None:
            (cert_dir / "fullchain.pem").write_bytes(previous_cert)
        else:
            (cert_dir / "fullchain.pem").unlink(missing_ok=True)
        if previous_key is not None:
            (cert_dir / "private.key").write_bytes(previous_key)
            os.chmod(cert_dir / "private.key", 0o600)
        else:
            (cert_dir / "private.key").unlink(missing_ok=True)
        subprocess.run(["nginx", "-t"], check=False)
        subprocess.run(["systemctl", "reload", "nginx"], check=False)
        atomic_json(status_path, {
            **status, "state": "error", "configured": active_path.exists(),
            "message": f"TLS activation failed and was rolled back: {exc}", "updated_at": utc_now(),
        })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-dir", default="/var/lib/dark-threat-radar/tls")
    parser.add_argument("--nginx-config", default="/etc/nginx/conf.d/dark-threat-radar.conf")
    parser.add_argument("--certificate-dir", default="/etc/nginx/dark-threat-radar-tls")
    parser.add_argument("--upstream-port", type=int, default=9220)
    args = parser.parse_args()
    control_dir = Path(args.control_dir)
    request_path = control_dir / "inbox" / "request.json"
    processed = None
    while True:
        try:
            if request_path.is_file():
                request = read_request(request_path)
                request_id = request.get("request_id")
                if request_id and request_id != processed:
                    validate_request(request, args.upstream_port)
                    apply_request(control_dir, Path(args.nginx_config), Path(args.certificate_dir), request)
                    processed = request_id
                    request_path.unlink(missing_ok=True)
                    request_dir = control_dir / "inbox" / "uploads" / request_id
                    if REQUEST_ID_RE.fullmatch(str(request_id)):
                        shutil.rmtree(request_dir, ignore_errors=True)
        except Exception as exc:
            atomic_json(control_dir / "status.json", {
                "state": "error", "configured": (control_dir / "active.json").exists(),
                "message": str(exc), "updated_at": utc_now(),
            })
            request_path.unlink(missing_ok=True)
        time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
