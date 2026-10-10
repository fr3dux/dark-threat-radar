"""TLS control-plane validation and secret-handling tests."""

import shutil
import subprocess

import pytest

from app.tls_manager import (
    queue_tls_configuration,
    tls_public_status,
    validate_certificate_bundle,
    validate_fqdn,
    validate_ports,
)
from scripts import tls_manager_daemon
from scripts.tls_manager_daemon import nginx_config


def create_certificate(tmp_path, hostname="radar.example.com"):
    if not shutil.which("openssl"):
        pytest.skip("openssl is required for certificate fixture generation")
    cert = tmp_path / "certificate.pem"
    key = tmp_path / "private.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2",
            "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
        ],
        check=True,
        capture_output=True,
    )
    return cert.read_bytes(), key.read_bytes()


def test_fqdn_and_listener_port_validation():
    assert validate_fqdn("Radar.Example.COM.") == "radar.example.com"
    assert validate_ports(80, 443, 9220) == (80, 443)
    with pytest.raises(ValueError):
        validate_fqdn("localhost")
    with pytest.raises(ValueError):
        validate_ports(9220, 443, 9220)
    with pytest.raises(ValueError):
        validate_ports(8443, 8443, 9220)


def test_certificate_key_hostname_validation_and_safe_status(tmp_path):
    certificate, private_key = create_certificate(tmp_path)
    work_dir = tmp_path / "validation"
    work_dir.mkdir()
    metadata = validate_certificate_bundle(
        certificate, private_key, b"", "radar.example.com", work_dir
    )
    assert metadata["expires_at"]
    assert (work_dir / "private.key").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="Certificate validation failed"):
        validate_certificate_bundle(certificate, private_key, b"", "other.example.com", tmp_path / "mismatch")

    control = tmp_path / "control"
    control.mkdir()
    (control / "ready").write_text("ready\n", encoding="utf-8")
    queued = queue_tls_configuration(
        "radar.example.com", 80, 443, True, certificate, private_key,
        control_dir=control, upstream_port=9220,
    )
    assert queued["state"] == "queued"
    assert queued["fqdn"] == "radar.example.com"
    assert "private_key_path" not in queued
    assert "certificate_path" not in queued
    assert "PRIVATE KEY" not in str(queued)
    public_status = tls_public_status(control)
    assert public_status["manager_ready"] is True
    assert public_status["application_port"] == 9220


def test_nginx_configuration_supports_custom_ports_and_redirect():
    rendered = nginx_config(
        {
            "fqdn": "radar.example.com", "http_port": 8080, "https_port": 8443,
            "upstream_port": 9220, "redirect_http": True,
        },
        cert_path="/secure/fullchain.pem",
        key_path="/secure/private.key",
    )
    assert "listen 8080;" in rendered
    assert "listen 8443 ssl;" in rendered
    assert "https://radar.example.com:8443$request_uri" in rendered
    assert "proxy_pass http://127.0.0.1:9220" in rendered
    assert "ssl_protocols TLSv1.2 TLSv1.3" in rendered


def test_tls_worker_rolls_back_nginx_and_certificates_on_failed_health_check(tmp_path, monkeypatch):
    control = tmp_path / "control"
    request_dir = control / "uploads" / ("a" * 32)
    request_dir.mkdir(parents=True)
    source_cert = request_dir / "fullchain.pem"
    source_key = request_dir / "private.key"
    source_cert.write_text("new certificate", encoding="utf-8")
    source_key.write_text("new key", encoding="utf-8")
    nginx_path = tmp_path / "nginx.conf"
    nginx_path.write_text("previous nginx configuration", encoding="utf-8")
    cert_dir = tmp_path / "active-certificates"
    cert_dir.mkdir()
    (cert_dir / "fullchain.pem").write_text("previous certificate", encoding="utf-8")
    (cert_dir / "private.key").write_text("previous key", encoding="utf-8")

    def fail_health(command):
        if command[0] == "curl":
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(tls_manager_daemon, "run", fail_health)
    monkeypatch.setattr(tls_manager_daemon.subprocess, "run", lambda *args, **kwargs: None)
    request = {
        "request_id": "a" * 32,
        "fqdn": "radar.example.com",
        "http_port": 80,
        "https_port": 443,
        "redirect_http": True,
        "upstream_port": 9220,
        "certificate_path": str(source_cert),
        "private_key_path": str(source_key),
    }
    tls_manager_daemon.apply_request(control, nginx_path, cert_dir, request)

    assert nginx_path.read_text(encoding="utf-8") == "previous nginx configuration"
    assert (cert_dir / "fullchain.pem").read_text(encoding="utf-8") == "previous certificate"
    assert (cert_dir / "private.key").read_text(encoding="utf-8") == "previous key"
    status = tls_public_status(control)
    assert status["state"] == "error"
    assert "rolled back" in status["message"]
