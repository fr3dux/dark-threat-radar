"""Safe staging and status helpers for the host-managed TLS reverse proxy."""

from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import PORT

TLS_CONTROL_DIR = Path(os.getenv("TLS_CONTROL_DIR", "/var/lib/dark-threat-radar/tls"))
MAX_PEM_BYTES = 32 * 1024
FQDN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$", re.I)


def atomic_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate_fqdn(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid FQDN") from exc
    if not FQDN_RE.fullmatch(ascii_name):
        raise ValueError("Enter a complete hostname such as radar.example.com")
    return ascii_name


def validate_ports(http_port: int, https_port: int, upstream_port: int = PORT) -> tuple[int, int]:
    for name, value in (("HTTP", http_port), ("HTTPS", https_port)):
        if not 1 <= value <= 65535:
            raise ValueError(f"{name} port must be between 1 and 65535")
        if value == upstream_port:
            raise ValueError(f"Port {value} is reserved for the internal application service")
    if http_port == https_port:
        raise ValueError("HTTP and HTTPS ports must be different")
    return http_port, https_port


def _write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def validate_certificate_bundle(
    certificate: bytes,
    private_key: bytes,
    chain: bytes,
    fqdn: str,
    work_dir: Path,
) -> dict[str, Any]:
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not certificate or not private_key:
        raise ValueError("Certificate and private key are required")
    if any(len(item) > MAX_PEM_BYTES for item in (certificate, private_key, chain)):
        raise ValueError("Each PEM upload must be 32 KB or smaller")
    if b"BEGIN CERTIFICATE" not in certificate or b"PRIVATE KEY" not in private_key:
        raise ValueError("Certificate and key must use PEM format")

    fullchain = certificate.rstrip() + b"\n"
    if chain.strip():
        fullchain += chain.strip() + b"\n"
    cert_path = work_dir / "fullchain.pem"
    key_path = work_dir / "private.key"
    _write_private(cert_path, fullchain)
    _write_private(key_path, private_key)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        decoded = ssl._ssl._test_decode_cert(str(cert_path))  # type: ignore[attr-defined]
        ssl.match_hostname(decoded, fqdn)
    except (ssl.SSLError, ssl.CertificateError, ValueError) as exc:
        raise ValueError(f"Certificate validation failed: {exc}") from exc

    not_after = decoded.get("notAfter")
    expires_at = None
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            raise ValueError("Certificate has expired")
        expires_at = expires.isoformat().replace("+00:00", "Z")

    issuer = ", ".join(f"{key}={value}" for group in decoded.get("issuer", ()) for key, value in group)
    subject = ", ".join(f"{key}={value}" for group in decoded.get("subject", ()) for key, value in group)
    return {
        "certificate_path": str(cert_path),
        "private_key_path": str(key_path),
        "expires_at": expires_at,
        "issuer": issuer,
        "subject": subject,
    }


def tls_public_status(control_dir: Path = TLS_CONTROL_DIR) -> dict[str, Any]:
    result: dict[str, Any] = {
        "manager_ready": (control_dir / "ready").is_file(),
        "state": "not_configured",
        "configured": False,
        "application_port": PORT,
    }
    for filename in ("active.json", "status.json"):
        path = control_dir / filename
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for key in (
            "state", "configured", "fqdn", "http_port", "https_port", "redirect_http",
            "issuer", "subject", "expires_at", "message", "updated_at", "request_id",
        ):
            if key in payload:
                result[key] = payload[key]
    return result


def queue_tls_configuration(
    fqdn: str,
    http_port: int,
    https_port: int,
    redirect_http: bool,
    certificate: bytes,
    private_key: bytes,
    chain: bytes = b"",
    control_dir: Path = TLS_CONTROL_DIR,
    upstream_port: int = PORT,
) -> dict[str, Any]:
    fqdn = validate_fqdn(fqdn)
    http_port, https_port = validate_ports(http_port, https_port, upstream_port)
    if not (control_dir / "ready").is_file():
        raise RuntimeError("TLS manager is not installed on this host")
    if tls_public_status(control_dir).get("state") in {"queued", "applying"}:
        raise RuntimeError("A TLS configuration change is already in progress")

    uploads = control_dir / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    request_id = uuid.uuid4().hex
    request_dir = uploads / request_id
    request_dir.mkdir(mode=0o700)
    try:
        metadata = validate_certificate_bundle(certificate, private_key, chain, fqdn, request_dir)
    except Exception:
        shutil.rmtree(request_dir, ignore_errors=True)
        raise
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    request = {
        "request_id": request_id,
        "fqdn": fqdn,
        "http_port": http_port,
        "https_port": https_port,
        "redirect_http": redirect_http,
        "upstream_port": upstream_port,
        "certificate_path": metadata.pop("certificate_path"),
        "private_key_path": metadata.pop("private_key_path"),
        **metadata,
        "requested_at": now,
    }
    try:
        atomic_json(control_dir / "status.json", {
            **request,
            "certificate_path": None,
            "private_key_path": None,
            "state": "queued",
            "configured": False,
            "message": "TLS configuration queued for validation and activation",
            "updated_at": now,
        })
        atomic_json(control_dir / "request.json", request)
    except Exception:
        shutil.rmtree(request_dir, ignore_errors=True)
        raise
    return tls_public_status(control_dir)
