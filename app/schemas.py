"""Pydantic v2 Models for ThreatRadar
Defines strict schemas for request queries, responses, and artifacts.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ==================== VERSION & HEALTH SCHEMAS ====================

class VersionResponse(BaseModel):
    version: str = Field(..., description="Semantic version string (SemVer)")
    app_name: str = Field(..., description="Application name")
    description: str = Field(..., description="Application description")
    release_date: str = Field(..., description="Release date in YYYY-MM-DD")
    author: str = Field(..., description="Author or Maintainer")
    license: str = Field(..., description="License identifier")


class FeedStatus(BaseModel):
    feed_name: str
    last_sync: Optional[str] = None
    status: str
    items_count: int = 0
    message: Optional[str] = None


class SyncState(BaseModel):
    is_syncing: bool
    started_at: Optional[str] = None
    elapsed_seconds: Optional[float] = None


class ConnectorHealth(BaseModel):
    source_name: str
    category: str
    state: str
    last_attempt: Optional[str] = None
    last_success: Optional[str] = None
    duration_seconds: float = 0
    items_received: int = 0
    items_created: int = 0
    items_updated: int = 0
    items_dropped: int = 0
    last_error: Optional[str] = None
    http_code: Optional[int] = None


class IntegrationKeyUpdate(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=512)


class OpenPhishSettingsUpdate(BaseModel):
    enabled: bool
    terms_accepted: bool


class PasswordLeakCheckRequest(BaseModel):
    sha1_prefix: str = Field(..., pattern=r"^[A-Fa-f0-9]{5}$")
    sha1_suffix: str = Field(..., pattern=r"^[A-Fa-f0-9]{35}$")


class EmailLeakCheckRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized.count("@") != 1:
            raise ValueError("A valid email address is required")
        local, domain = normalized.rsplit("@", 1)
        if not local or not domain or "." not in domain or any(ch.isspace() for ch in normalized):
            raise ValueError("A valid email address is required")
        return normalized


class WatchlistCreate(BaseModel):
    item_type: Literal["vendor", "product", "cve"] = "vendor"
    value: str = Field(..., min_length=1, max_length=200)
    notes: str = Field(default="", max_length=500)

    @field_validator("value", "notes")
    @classmethod
    def strip_control_characters(cls, value: str) -> str:
        normalized = value.strip()
        if any(ord(ch) < 32 and ch not in "\t" for ch in normalized):
            raise ValueError("Control characters are not allowed")
        return normalized

    @field_validator("value")
    @classmethod
    def require_value(cls, value: str) -> str:
        if not value:
            raise ValueError("Value cannot be empty")
        return value


class StatusResponse(BaseModel):
    version: str
    feeds: List[FeedStatus]
    sync: SyncState
    connectors: List[ConnectorHealth] = []


# ==================== STATS & METRICS SCHEMAS ====================

class InfoconStatus(BaseModel):
    status: str
    updated_at: Optional[str] = None
    raw_json: Optional[str] = None


class TopVendor(BaseModel):
    vendor_project: str
    count: int


class TopMalware(BaseModel):
    signature: str
    count: int


class TopPort(BaseModel):
    port: int
    service: Optional[str] = None
    count: Optional[int] = None
    records: Optional[int] = None
    targets: Optional[int] = None


class RecentKev(BaseModel):
    cve_id: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    due_date: Optional[str] = None
    known_ransomware_campaign_use: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None


class RecentNews(BaseModel):
    id: str
    title: str
    source: str
    published_date: Optional[str] = None
    link: str
    snippet: Optional[str] = None


class CvssDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    scored_total: int = 0


class DashboardStats(BaseModel):
    total_cves: int = 0
    total_kev: int = 0
    total_critical_cves: int = 0
    total_high_cves: int = 0
    total_medium_cves: int = 0
    total_low_cves: int = 0
    total_ransomware: int = 0
    total_malware: int = 0
    infocon: InfoconStatus
    total_dshield_ips: int = 0
    total_dshield_ports: int = 0
    total_news: int = 0
    cvss_distribution: CvssDistribution
    top_vendors: List[TopVendor] = []
    top_malware: List[TopMalware] = []
    recent_kevs: List[RecentKev] = []
    top_ports: List[TopPort]
    recent_critical_vendors: Optional[List[Dict[str, Any]]] = None
    recent_ransomware_victims: Optional[List[Dict[str, Any]]] = None
    recent_news: List[RecentNews] = []


class StatsResponse(BaseModel):
    version: str
    stats: DashboardStats
    feeds: List[FeedStatus]
    sync: SyncState
    connectors: List[ConnectorHealth] = []


# ==================== CVE SCHEMAS ====================

class CVERecord(BaseModel):
    cve_id: str
    source: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None
    known_ransomware_campaign_use: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    raw_json: Optional[str] = None
    updated_at: Optional[str] = None


class PaginatedResponse(BaseModel):
    total: int
    limit: int
    offset: int


class CVEListResponse(PaginatedResponse):
    items: List[CVERecord]


# ==================== MALWARE SCHEMAS ====================

class MalwareSample(BaseModel):
    sha256_hash: str
    md5_hash: Optional[str] = None
    sha1_hash: Optional[str] = None
    first_seen: Optional[str] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    signature: Optional[str] = None
    reporter: Optional[str] = None
    delivery_method: Optional[str] = None
    tags: Optional[str] = None
    raw_json: Optional[str] = None
    updated_at: Optional[str] = None


class MalwareListResponse(PaginatedResponse):
    items: List[MalwareSample]


# ==================== DSHIELD SCHEMAS ====================

class DShieldSource(BaseModel):
    ip: str
    attacks: Optional[int] = None
    count: Optional[int] = None
    firstseen: Optional[str] = None
    lastseen: Optional[str] = None
    as_name: Optional[str] = None
    updated_at: Optional[str] = None


class DShieldPort(BaseModel):
    port: int
    count: Optional[int] = None
    records: Optional[int] = None
    targets: Optional[int] = None
    service: Optional[str] = None
    updated_at: Optional[str] = None


class DShieldResponse(BaseModel):
    infocon: InfoconStatus
    sources: List[DShieldSource]
    ports: List[DShieldPort]


# ==================== NEWS SCHEMAS ====================

class NewsItem(BaseModel):
    id: str
    title: str
    link: str
    source: str
    published_date: Optional[str] = None
    snippet: Optional[str] = None
    updated_at: Optional[str] = None


class NewsListResponse(PaginatedResponse):
    items: List[NewsItem]


# ==================== ARTIFACT & ERROR SCHEMAS ====================

class ArtifactResponse(BaseModel):
    type: str
    identifier: str
    data: Dict[str, Any]


class ErrorResponse(BaseModel):
    error: str
    status_code: int
    detail: Optional[Any] = None


# ==================== RANSOMWARE SCHEMAS (v1.2.0) ====================

class RansomwareVictim(BaseModel):
    id: str
    victim_name: str
    group_name: str
    country: Optional[str] = None
    activity: Optional[str] = None
    domain: Optional[str] = None
    discovered: Optional[str] = None
    attackdate: Optional[str] = None
    description: Optional[str] = None
    claim_url: Optional[str] = None
    screenshot: Optional[str] = None
    url: Optional[str] = None
    updated_at: Optional[str] = None


class RansomwareListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    brazil_total: int
    items: List[RansomwareVictim]
