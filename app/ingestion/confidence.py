"""Confidence Scoring Engine for Dark Threat Radar (0-100 scale)
Calculates threat indicator confidence based on source reliability,
multi-source correlation, recency, active status, and false-positive risk.
"""

from typing import List, Optional, Dict, Any

# Base reliability by source
SOURCE_BASE_SCORES = {
    "cisa_kev": 95,
    "nvd_cve": 90,
    "vendor_advisories": 95,
    "spamhaus_drop": 95,
    "github_advisories": 88,
    "osv_dev": 85,
    "threatfox": 80,
    "feodo_tracker": 82,
    "urlhaus": 78,
    "malware_bazaar": 80,
    "ransomware_live": 85,
    "sslbl": 70,
    "dshield": 65,
    "openphish": 60,
    "certbr": 75,
    "news_feed": 50,
}

# Cloud / Shared Infrastructure ASNs or Keywords for FP mitigation
SHARED_INFRA_KEYWORDS = {
    "cloudflare", "akamai", "fastly", "amazon", "aws", "azure", "microsoft",
    "google", "gcp", "ovh", "hetzner", "digitalocean", "linode"
}


def calculate_confidence(
    source_name: str,
    indicator_type: str,
    active: bool = True,
    sources_count: int = 1,
    in_spamhaus_drop: bool = False,
    asn_name: Optional[str] = None,
    raw_metadata: Optional[Dict[str, Any]] = None
) -> int:
    """Calculate normalized confidence score from 0 to 100.
    
    Ranges:
    - 90-100: Official confirmation or multi-source high trust
    - 70-89: Reliable & recent active indicator
    - 40-69: Contextual or unconfirmed
    - <40: Low confidence / High FP risk (e.g., JA3, shared cloud IPs)
    """
    base = SOURCE_BASE_SCORES.get(source_name.lower(), 50)
    score = base

    # Multi-source boost (+10 per additional source, up to +30)
    if sources_count > 1:
        score += min(30, (sources_count - 1) * 10)

    # Spamhaus DROP boost (+15)
    if in_spamhaus_drop:
        score += 15

    # Status penalty if inactive or revoked
    if not active:
        score -= 25

    # Indicator Type Adjustments / FP Penalties
    if indicator_type == "JA3":
        # JA3 fingerprints can produce high false positives across different apps
        score = min(score, 45)

    if indicator_type in ("IPv4", "IPv6", "domain") and asn_name:
        asn_lower = asn_name.lower()
        if any(kw in asn_lower for kw in SHARED_INFRA_KEYWORDS):
            # Shared CDN/Cloud IP - penalize to avoid blocking legitimate services
            score = min(score, 60)

    # Clamp score strictly between 0 and 100
    final_score = max(0, min(100, score))
    return int(final_score)


def get_confidence_severity_label(confidence: int) -> str:
    """Return human readable severity tier from confidence score."""
    if confidence >= 90:
        return "CRITICAL"
    elif confidence >= 70:
        return "HIGH"
    elif confidence >= 40:
        return "MEDIUM"
    else:
        return "LOW"
