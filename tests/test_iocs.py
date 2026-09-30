"""Tests for IOC Normalization, Confidence Scoring, and Multi-Source Correlation (v1.8.0)
"""

import pytest
from app.ingestion.normalization import (
    normalize_domain, normalize_url, normalize_ip, normalize_hash,
    normalize_cve, normalize_ghsa, normalize_indicator, generate_ioc_id,
    TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN, TYPE_URL, TYPE_SHA256, TYPE_MD5, TYPE_CVE, TYPE_GHSA
)
from app.ingestion.confidence import calculate_confidence, get_confidence_severity_label


def test_domain_normalization():
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("http://sub.domain.com:8080/path") == "sub.domain.com"
    assert normalize_domain("invalid_domain!@#$") is None


def test_url_normalization():
    assert normalize_url("HTTP://EXAMPLE.COM/path?arg=1") == "http://example.com/path?arg=1"
    assert normalize_url("malicious-site.org/payload.exe") == "http://malicious-site.org/payload.exe"


def test_ip_normalization():
    ip4, t4 = normalize_ip("192.168.1.1:8080")
    assert ip4 == "192.168.1.1"
    assert t4 == TYPE_IPV4

    ip6, t6 = normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert ip6 == "2001:db8:85a3::8a2e:370:7334"
    assert t6 == TYPE_IPV6

    bad_ip, _ = normalize_ip("999.999.999.999")
    assert bad_ip is None


def test_hash_normalization():
    h32, t_md5 = normalize_hash("5D41402ABC4B2A76B9719D911017C592")
    assert h32 == "5d41402abc4b2a76b9719d911017c592"
    assert t_md5 == TYPE_MD5

    h64, t_sha256 = normalize_hash("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    assert h64 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert t_sha256 == TYPE_SHA256

    bad_h, _ = normalize_hash("not_a_hash_z123")
    assert bad_h is None


def test_cve_ghsa_normalization():
    assert normalize_cve("cve-2024-21762") == "CVE-2024-21762"
    assert normalize_ghsa("ghsa-77rw-f484-hj39") == "GHSA-77RW-F484-HJ39"


def test_confidence_scoring():
    # CISA KEV or Spamhaus DROP high score
    score_drop = calculate_confidence("spamhaus_drop", TYPE_IPV4, active=True, in_spamhaus_drop=True)
    assert score_drop >= 90
    assert get_confidence_severity_label(score_drop) == "CRITICAL"

    # JA3 fingerprint FP discount cap
    score_ja3 = calculate_confidence("sslbl", "JA3", active=True)
    assert score_ja3 <= 45

    # Multi-source correlation boost
    score_multi = calculate_confidence("threatfox", TYPE_DOMAIN, active=True, sources_count=3)
    score_single = calculate_confidence("threatfox", TYPE_DOMAIN, active=True, sources_count=1)
    assert score_multi > score_single


def test_deterministic_ioc_id():
    id1 = generate_ioc_id(TYPE_IPV4, "1.1.1.1")
    id2 = generate_ioc_id(TYPE_IPV4, "1.1.1.1")
    assert id1 == id2
    assert len(id1) == 24
