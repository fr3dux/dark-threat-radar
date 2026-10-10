#!/usr/bin/env python3
"""Root-owned Nginx TLS configuration worker with validation and rollback."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

FQDN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$", re.I)
REQUEST_ID_RE = re.compile(r"^[a-f0-9]{32}$")


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


def safe_request_path(value: str, control_dir: Path) -> Path:
    path = Path(value).resolve()
    uploads = (control_dir / "uploads").resolve()
    if uploads not in path.parents:
        raise ValueError("Certificate request path is outside the TLS control directory")
    return path


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
        source_cert = safe_request_path(request["certificate_path"], control_dir)
        source_key = safe_request_path(request["private_key_path"], control_dir)
        cert_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_cert, cert_dir / "fullchain.pem")
        shutil.copyfile(source_key, cert_dir / "private.key")
        os.chmod(cert_dir / "fullchain.pem", 0o600)
        os.chmod(cert_dir / "private.key", 0o600)
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
    request_path = control_dir / "request.json"
    processed = None
    while True:
        try:
            if request_path.is_file():
                request = json.loads(request_path.read_text(encoding="utf-8"))
                request_id = request.get("request_id")
                if request_id and request_id != processed:
                    validate_request(request, args.upstream_port)
                    apply_request(control_dir, Path(args.nginx_config), Path(args.certificate_dir), request)
                    processed = request_id
                    request_path.unlink(missing_ok=True)
                    request_dir = control_dir / "uploads" / request_id
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
