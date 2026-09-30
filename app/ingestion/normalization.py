"""IOC Normalization and Deduplication Engine for Dark Threat Radar
Handles domain IDNA conversion, URL canonicalization, IP validation, hash validation,
and alias mapping (CVE / GHSA / OSV).
"""

import re
import idna
import hashlib
import ipaddress
from urllib.parse import urlsplit, urlunsplit
from typing import Optional, Tuple, Dict, Any, List

# Indicator Type Constants
TYPE_IPV4 = "IPv4"
TYPE_IPV6 = "IPv6"
TYPE_CIDR = "CIDR"
TYPE_ASN = "ASN"
TYPE_DOMAIN = "domain"
TYPE_HOSTNAME = "hostname"
TYPE_URL = "URL"
TYPE_SHA256 = "SHA-256"
TYPE_SHA1 = "SHA-1"
TYPE_MD5 = "MD5"
TYPE_TLS_CERT = "TLS Certificate"
TYPE_JA3 = "JA3"
TYPE_CVE = "CVE"
TYPE_GHSA = "GHSA"
TYPE_PACKAGE = "Software Package"

SUPPORTED_TYPES = {
    TYPE_IPV4, TYPE_IPV6, TYPE_CIDR, TYPE_ASN, TYPE_DOMAIN, TYPE_HOSTNAME,
    TYPE_URL, TYPE_SHA256, TYPE_SHA1, TYPE_MD5, TYPE_TLS_CERT, TYPE_JA3,
    TYPE_CVE, TYPE_GHSA, TYPE_PACKAGE
}


def normalize_domain(domain_str: str) -> Optional[str]:
    """Convert domain to lowercase and IDNA encoded format."""
    if not domain_str or not isinstance(domain_str, str):
        return None
    d = domain_str.strip().lower().rstrip('.')
    if "://" in d:
        d = urlsplit(d).hostname or d
    elif d.startswith("[") and "]" in d:
        d = d[1:d.index("]")]
    elif d.count(":") == 1:
        host, port = d.rsplit(":", 1)
        if port.isdigit():
            d = host
    try:
        return idna.encode(d).decode('ascii')
    except Exception:
        if re.match(r'^[a-z0-9\.\-_]+$', d):
            return d
        return None


def normalize_url(url_str: str) -> Optional[str]:
    """Canonicalize URL without destroying parameters."""
    if not url_str or not isinstance(url_str, str):
        return None
    u = url_str.strip()
    if not u.lower().startswith(("http://", "https://", "ftp://")):
        u = 'http://' + u
    try:
        parsed = urlsplit(u)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https", "ftp"} or not parsed.hostname:
            return None
        host = idna.encode(parsed.hostname.rstrip(".")).decode("ascii").lower()
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        path = parsed.path or '/'
        return urlunsplit((scheme, host, path, parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def normalize_ip(ip_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Validate and normalize IPv4/IPv6 address.
    Returns (normalized_ip, indicator_type)
    """
    if not ip_str or not isinstance(ip_str, str):
        return None, None
    s = ip_str.strip()
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1:
        host, port = s.rsplit(":", 1)
        if port.isdigit():
            s = host
    try:
        ip_obj = ipaddress.ip_address(s)
        if ip_obj.version == 4:
            return str(ip_obj), TYPE_IPV4
        else:
            return str(ip_obj), TYPE_IPV6
    except ValueError:
        return None, None


def normalize_hash(hash_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Normalize and validate MD5, SHA-1, SHA-256 hash.
    Returns (normalized_hash, indicator_type)
    """
    if not hash_str or not isinstance(hash_str, str):
        return None, None
    h = hash_str.strip().lower()
    if not re.match(r'^[a-f0-9]+$', h):
        return None, None
    length = len(h)
    if length == 32:
        return h, TYPE_MD5
    elif length == 40:
        return h, TYPE_SHA1
    elif length == 64:
        return h, TYPE_SHA256
    return None, None


def normalize_cve(cve_str: str) -> Optional[str]:
    """Normalize CVE ID (e.g. CVE-2024-1234)."""
    if not cve_str or not isinstance(cve_str, str):
        return None
    match = re.search(r'CVE-\d{4}-\d{4,7}', cve_str.strip(), re.IGNORECASE)
    if match:
        return match.group(0).upper()
    return None


def normalize_ghsa(ghsa_str: str) -> Optional[str]:
    """Normalize GHSA ID (e.g. GHSA-xxxx-xxxx-xxxx)."""
    if not ghsa_str or not isinstance(ghsa_str, str):
        return None
    match = re.search(r'GHSA-[2-9a-z]{4}-[2-9a-z]{4}-[2-9a-z]{4}', ghsa_str.strip(), re.IGNORECASE)
    if match:
        return match.group(0).upper()
    return None


def normalize_indicator(indicator_type: str, indicator_value: str) -> Tuple[Optional[str], Optional[str]]:
    """Normalize indicator according to its type.
    Returns (normalized_value, detected_type)
    """
    if not indicator_value or not isinstance(indicator_value, str):
        return None, None

    val = indicator_value.strip()

    if indicator_type in (TYPE_IPV4, TYPE_IPV6):
        return normalize_ip(val)
    elif indicator_type in (TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
        return normalize_hash(val)
    elif indicator_type in (TYPE_DOMAIN, TYPE_HOSTNAME):
        norm = normalize_domain(val)
        return norm, TYPE_DOMAIN if norm else None
    elif indicator_type == TYPE_URL:
        norm = normalize_url(val)
        return norm, TYPE_URL if norm else None
    elif indicator_type == TYPE_CVE:
        norm = normalize_cve(val)
        return norm, TYPE_CVE if norm else None
    elif indicator_type == TYPE_GHSA:
        norm = normalize_ghsa(val)
        return norm, TYPE_GHSA if norm else None
    elif indicator_type == TYPE_ASN:
        v = val.upper()
        if not v.startswith("AS"):
            v = f"AS{v}"
        return v, TYPE_ASN
    elif indicator_type == TYPE_CIDR:
        try:
            net = ipaddress.ip_network(val, strict=False)
            return str(net), TYPE_CIDR
        except ValueError:
            return None, None
    elif indicator_type == TYPE_JA3:
        if len(val) == 32 and re.match(r'^[a-f0-9]{32}$', val, re.I):
            return val.lower(), TYPE_JA3
        return None, None
    elif indicator_type == TYPE_TLS_CERT:
        h_norm, h_type = normalize_hash(val)
        return h_norm, TYPE_TLS_CERT if h_norm else None
    else:
        return val.strip(), indicator_type


def generate_ioc_id(indicator_type: str, normalized_value: str) -> str:
    """Generate a deterministic ID for an IOC record."""
    raw = f"{indicator_type.lower()}:{normalized_value.lower()}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]
