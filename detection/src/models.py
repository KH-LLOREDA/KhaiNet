"""Pydantic v2 models for the KhaiNet detection pipeline.

All models follow the same conventions as brain/src/models.py and
tuning/src/models.py:

- ``from __future__ import annotations``
- ``ConfigDict(extra="ignore")`` where appropriate
- Timestamps accept datetime, ISO-8601 string (with or without 'Z'), or epoch
- IPs are pseudonymized hashes (SHA-256), never real IPs
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_timestamp(v: Any) -> datetime:
    """Accept datetime, ISO-8601 string (with or without 'Z'), or epoch float."""
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        v = v.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    raise ValueError(f"Invalid timestamp: {v}")


# ---------------------------------------------------------------------------
# Zeek log models
# ---------------------------------------------------------------------------


class ZeekConn(BaseModel):
    """A connection record from Zeek's conn.log."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    uid: str
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    src_port: int
    dst_port: int
    protocol: str  # tcp, udp, icmp
    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    service: str | None = None
    conn_state: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()

    @property
    def bytes_total(self) -> int:
        return self.orig_bytes + self.resp_bytes

    @property
    def pkts_total(self) -> int:
        return self.orig_pkts + self.resp_pkts


class ZeekDNS(BaseModel):
    """A DNS query record from Zeek's dns.log."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    uid: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    query: str
    qclass: int = 0
    qtype: str = "A"
    rcode: str = "NOERROR"
    rcode_name: str = "NOERROR"
    answers: list[str] = Field(default_factory=list)
    ttl: list[int] = Field(default_factory=list)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()

    @property
    def is_nxdomain(self) -> bool:
        return self.rcode in ("NXDOMAIN", "SERVFAIL")


class ZeekHTTP(BaseModel):
    """An HTTP request record from Zeek's http.log."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    uid: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    method: str  # GET, POST, etc.
    host: str
    uri: str
    user_agent: str | None = None
    status_code: int | None = None
    request_body_len: int = 0
    response_body_len: int = 0

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class ZeekSSL(BaseModel):
    """An SSL/TLS handshake record from Zeek's ssl.log."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    uid: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    version: str | None = None
    cipher: str | None = None
    server_name: str | None = None  # SNI
    resumed: bool = False
    subject: str | None = None
    issuer: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Feature models
# ---------------------------------------------------------------------------


class FeatureVector(BaseModel):
    """Vector of features per event, for Isolation Forest and Autoencoder."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    src_ip: str
    dst_ip: str
    # Connection
    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    bytes_total: int
    bytes_ratio: float  # orig/total
    # Destination
    dst_port: int
    is_common_port: bool  # 80, 443, 22, 53, 25
    # Temporal
    hour_of_day: float  # 0-23
    day_of_week: float  # 0-6
    is_weekend: bool
    # Aggregated by host (require context)
    unique_destinations: int = 0
    unique_ports: int = 0
    dns_queries_count: int = 0
    nxdomain_ratio: float = 0.0
    avg_dns_query_length: float = 0.0
    # Normalized vector (filled by feature_engineering)
    normalized: list[float] = Field(default_factory=list)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class WindowFeatures(BaseModel):
    """Features aggregated by temporal window (5 min) for HMM."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    src_ip: str
    window_start: datetime
    window_end: datetime
    bytes_out: int
    bytes_in: int
    pkts_total: int
    unique_destinations: int
    unique_ports: int
    dns_queries: int
    nxdomain_ratio: float
    avg_duration: float
    connection_count: int

    @field_validator("timestamp", "window_start", "window_end", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Detection result models
# ---------------------------------------------------------------------------


class ModelResult(BaseModel):
    """Result of a detection model."""

    model_config = ConfigDict(extra="ignore")

    model_name: str  # isolation_forest, autoencoder, hmm
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    src_ip: str
    score: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool = False
    threshold: float = 0.5
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @field_validator("score", mode="before")
    @classmethod
    def clamp_score(cls, v: Any) -> float:
        v = float(v)
        return max(0.0, min(1.0, v))

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Baseline models
# ---------------------------------------------------------------------------


class BaselineStats(BaseModel):
    """Baseline statistics per host/service."""

    model_config = ConfigDict(extra="ignore")

    src_ip: str
    service: str | None = None
    metric: str  # bytes_out, duration, unique_destinations, etc.
    mean: float
    std: float
    min_val: float
    max_val: float
    p50: float
    p95: float
    p99: float
    sample_count: int
    window_hours: int = 24


class StateMapping(BaseModel):
    """Mapping of HMM states to semantics (post-training)."""

    model_config = ConfigDict(extra="ignore")

    state_id: int
    label: str  # normal, scan, exfil, c2
    confidence: float = Field(ge=0.0, le=1.0)
    mean_features: dict[str, float] = Field(default_factory=dict)
