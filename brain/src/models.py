"""Pydantic models for KhaiNet Brain.

All models use strict validation. IPs are pseudonymized (hash) as per GDPR.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SourceType(str, Enum):
    ANOMALY = "anomaly"
    SIGNATURE = "signature"
    HOST = "host"


class EventType(str, Enum):
    SCAN = "scan"
    C2_BEACONING = "c2_beaconing"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    DNS_TUNNELING = "dns_tunneling"
    ANOMALY = "anomaly"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class SeverityLabel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ActionPriority(str, Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FeedbackVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


# ---------------------------------------------------------------------------
# Input: Alert
# ---------------------------------------------------------------------------


class Alert(BaseModel):
    """Pre-filtered alert from ML models, Suricata or Wazuh."""

    model_config = ConfigDict(extra="ignore", use_enum_values=True)

    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    source: str
    source_type: SourceType
    severity_raw: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    protocol: Protocol
    event_type: EventType

    src_port: int | None = None
    dst_port: int | None = None
    service: str | None = None
    bytes: int | None = None
    packets: int | None = None
    duration: float | None = None
    ml_model: str | None = None
    ml_score: float | None = None
    ml_features: dict[str, Any] = Field(default_factory=dict)
    rule_id: str | None = None
    rule_message: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw_event: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        """Accept ISO-8601 strings with or without trailing 'Z'."""
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            v = v.replace("Z", "+00:00")
            return datetime.fromisoformat(v)
        raise ValueError(f"Invalid timestamp: {v}")

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


class AssetInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    hostname: str | None = None
    type: str | None = None  # server, workstation, IoT
    criticality: int = Field(default=2, ge=1, le=5)
    os: str | None = None
    services: list[str] = Field(default_factory=list)
    owner: str | None = None


class GeoIpInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    dst_country: str | None = None
    dst_city: str | None = None
    dst_asn: str | None = None
    dst_asn_org: str | None = None


class ThreatIntelInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    dst_ip_malicious: bool = False
    dst_ip_tags: list[str] = Field(default_factory=list)
    src_ip_malicious: bool = False
    src_ip_tags: list[str] = Field(default_factory=list)
    source: str = "MISP"


class HistoricalContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    first_seen_dst: str | None = None
    baseline_bytes_out_p99: float | None = None
    actual_bytes_out: float | None = None
    deviation_factor: float | None = None


class EnrichmentData(BaseModel):
    """Aggregated enrichment from all sources (asset, GeoIP, MISP, historical)."""

    model_config = ConfigDict(extra="allow")

    asset_info: AssetInfo = Field(default_factory=AssetInfo)
    geoip: GeoIpInfo = Field(default_factory=GeoIpInfo)
    threat_intel: ThreatIntelInfo = Field(default_factory=ThreatIntelInfo)
    historical_context: HistoricalContext = Field(default_factory=HistoricalContext)
    partial: bool = False
    failed_sources: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


class AlertGroup(BaseModel):
    """A group of correlated alerts sharing an entity and/or attack pattern."""

    model_config = ConfigDict(extra="allow")

    alerts: list[Alert]
    entity: str  # src_ip (pseudonymized)
    reason: str = "shared_source_proximity"
    pattern_name: str | None = None

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def get_src_ips(self) -> list[str]:
        return list({a.src_ip for a in self.alerts})

    def get_dst_ips(self) -> list[str]:
        return list({a.dst_ip for a in self.alerts})

    def get_src_hosts(self) -> list[str]:
        hosts: list[str] = []
        for a in self.alerts:
            if a.raw_event.get("hostname") and a.raw_event["hostname"] not in hosts:
                hosts.append(a.raw_event["hostname"])
        return hosts

    def time_span_seconds(self) -> float:
        if len(self.alerts) < 2:
            return 0.0
        ts = [a.ts_epoch for a in self.alerts]
        return max(ts) - min(ts)

    def unique_sources(self) -> int:
        return len({a.source for a in self.alerts})

    def unique_destinations(self) -> int:
        return len({a.dst_ip for a in self.alerts})


# ---------------------------------------------------------------------------
# Output: Incident
# ---------------------------------------------------------------------------


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    target: str
    priority: ActionPriority = ActionPriority.MEDIUM
    auto_execute: bool = False
    justification: str = ""


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: str
    event: str


class IncidentMetrics(BaseModel):
    model_config = ConfigDict(extra="allow")

    alert_count: int = 0
    time_span_seconds: float = 0.0
    unique_sources: int = 0
    unique_destinations: int = 0


class IncidentEntities(BaseModel):
    model_config = ConfigDict(extra="allow")

    src_hosts: list[str] = Field(default_factory=list)
    dst_hosts: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    """Correlated incident produced by Brain."""

    model_config = ConfigDict(extra="allow", use_enum_values=True)

    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: IncidentStatus = IncidentStatus.NEW
    severity: int = Field(ge=0, le=100)
    severity_label: SeverityLabel
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    explanation: str | None = None
    correlation_reason: str
    false_positive_assessment: str
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    entities: IncidentEntities = Field(default_factory=IncidentEntities)
    enrichment: EnrichmentData = Field(default_factory=EnrichmentData)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    metrics: IncidentMetrics = Field(default_factory=IncidentMetrics)
    xai_available: bool = False
    llm_model: str | None = None
    llm_latency_ms: int | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("created_at", mode="before")
    @classmethod
    def parse_created_at(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            v = v.replace("Z", "+00:00")
            return datetime.fromisoformat(v)
        raise ValueError(f"Invalid created_at: {v}")

    def model_dump_json_safe(self) -> dict[str, Any]:
        """Serialize to dict with ISO timestamps (for Kafka / Shuffle)."""
        d = self.model_dump(mode="json")
        return d


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------


class AnalystFeedback(BaseModel):
    """Feedback from SOC analyst or Shuffle about an incident."""

    model_config = ConfigDict(extra="ignore", use_enum_values=True)

    feedback_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    analyst: str
    verdict: FeedbackVerdict
    reason: str = ""
    original_severity: int | None = None
    adjusted_severity: int | None = None
    severity_adjustment: int | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            v = v.replace("Z", "+00:00")
            return datetime.fromisoformat(v)
        raise ValueError(f"Invalid timestamp: {v}")


# ---------------------------------------------------------------------------
# LLM output schema (for validation)
# ---------------------------------------------------------------------------


class LLMRecommendedAction(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    target: str
    priority: str = "medium"
    auto_execute: bool = False
    justification: str = ""


class LLMOutput(BaseModel):
    """Validated output from the LLM."""

    model_config = ConfigDict(extra="ignore")

    title: str = Field(max_length=100)
    description: str
    explanation: str
    correlation_reason: str
    false_positive_assessment: str
    severity_adjustment: int = Field(default=0, ge=-20, le=20)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_actions: list[LLMRecommendedAction] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# DLQ message
# ---------------------------------------------------------------------------


class DLQMessage(BaseModel):
    """Message sent to the Dead Letter Queue."""

    model_config = ConfigDict(extra="allow")

    original_message: dict[str, Any]
    error: str
    error_type: str
    component: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    topic: str | None = None
    partition: int | None = None
    offset: int | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            v = v.replace("Z", "+00:00")
            return datetime.fromisoformat(v)
        raise ValueError(f"Invalid timestamp: {v}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def severity_to_label(score: int) -> SeverityLabel:
    """Map a 0-100 score to a severity label."""
    if score >= 80:
        return SeverityLabel.CRITICAL
    if score >= 60:
        return SeverityLabel.HIGH
    if score >= 40:
        return SeverityLabel.MEDIUM
    return SeverityLabel.LOW


def label_to_playbook(label: str | SeverityLabel) -> str:
    """Map a severity label to a Shuffle playbook name."""
    if isinstance(label, SeverityLabel):
        label = label.value
    mapping = {
        "critical": "brain-critical-response",
        "high": "brain-high-response",
        "medium": "brain-medium-response",
        "low": "brain-low-response",
    }
    return mapping.get(label, "brain-low-response")
