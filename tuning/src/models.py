"""Pydantic v2 models for the KhaiNet tuning pipeline.

All models follow the same conventions as brain/src/models.py:
- ``from __future__ import annotations``
- ``ConfigDict(extra="ignore")`` where appropriate
- Timestamps accept ISO-8601 strings with or without trailing 'Z'
- IPs are pseudonymized hashes (never real IPs)
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
    """Accept datetime or ISO-8601 string (with or without trailing 'Z')."""
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        v = v.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    raise ValueError(f"Invalid timestamp: {v}")


# ---------------------------------------------------------------------------
# Darktrace alert (raw API response → model)
# ---------------------------------------------------------------------------


class DarktraceAlert(BaseModel):
    """An alert fetched from the Darktrace REST API.

    IPs are pseudonymized hashes as per GDPR compliance.
    """

    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    model_name: str
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "tcp"
    category: str = ""
    severity: str = "medium"  # low|medium|high|critical
    description: str = ""
    devices: list[dict[str, Any]] = Field(default_factory=list)
    pbid: str | None = None
    priority: int = 0

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        """Epoch seconds for fast temporal comparison."""
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Supervised label (ground truth from Darktrace)
# ---------------------------------------------------------------------------


class SupervisedLabel(BaseModel):
    """A supervised label derived from a Darktrace alert.

    ``label=True`` means the event is a confirmed anomaly/attack.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    label: bool
    source: str = "darktrace"
    darktrace_alert_id: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    event_type: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Model score (output of the 3 ML models)
# ---------------------------------------------------------------------------


class ModelScore(BaseModel):
    """A score (0-1) produced by one of the 3 ML models for a network event."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    model_name: str
    score: float = Field(ge=0.0, le=1.0)
    features: dict[str, Any] = Field(default_factory=dict)

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
# Aligned event (event + matched label)
# ---------------------------------------------------------------------------


class AlignedEvent(BaseModel):
    """A model score aligned with a supervised label via temporal matching.

    ``match_distance_seconds`` is the absolute time difference between the
    event and the matched label (``None`` if no match was found).
    ``match_confidence`` decreases with distance and jitter.
    """

    model_config = ConfigDict(extra="ignore")

    event: ModelScore
    label: bool = False
    match_distance_seconds: float | None = None
    match_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_label_id: str | None = None

    @property
    def score(self) -> float:
        return self.event.score

    @property
    def model_name(self) -> str:
        return self.event.model_name

    @property
    def timestamp(self) -> datetime:
        return self.event.timestamp

    @property
    def src_ip(self) -> str:
        return self.event.src_ip

    @property
    def dst_ip(self) -> str:
        return self.event.dst_ip


# ---------------------------------------------------------------------------
# Tuning result (per model)
# ---------------------------------------------------------------------------


class TuningResult(BaseModel):
    """Result of threshold tuning for a single model."""

    model_config = ConfigDict(extra="ignore")

    model_name: str
    optimal_threshold: float = Field(ge=0.0, le=1.0)
    precision_at_threshold: float = Field(ge=0.0, le=1.0)
    recall_at_threshold: float = Field(ge=0.0, le=1.0)
    f1_at_threshold: float = Field(ge=0.0, le=1.0)
    pr_auc: float = Field(ge=0.0, le=1.0)
    roc_auc: float = Field(ge=0.0, le=1.0)
    youdens_j: float = Field(ge=-1.0, le=1.0)
    cost_at_threshold: float = 0.0
    threshold_curve: list[dict[str, Any]] = Field(default_factory=list)
    # Reference thresholds (for comparison)
    f1_optimal_threshold: float | None = None
    youdens_optimal_threshold: float | None = None


# ---------------------------------------------------------------------------
# Fusion result (ensemble)
# ---------------------------------------------------------------------------


class FusionResult(BaseModel):
    """Result of fusing scores from the 3 models into a unified score."""

    model_config = ConfigDict(extra="ignore")

    method: str  # weighted_average | stacking
    weights: dict[str, float] = Field(default_factory=dict)
    unified_score: float = Field(default=0.0, ge=0.0, le=1.0)
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    model_contributions: dict[str, Any] = Field(default_factory=dict)
    # For stacking: serialized meta-model coefficients
    meta_model_params: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Confusion matrix
# ---------------------------------------------------------------------------


class ConfusionMatrix(BaseModel):
    """2×2 confusion matrix comparing KhaiNet predictions vs Darktrace labels.

    Layout:
                        Darktrace detecta    Darktrace no detecta
    KhaiNet detecta     TP                   FP (ventaja)
    KhaiNet no detecta  FN (gap cobertura)   TN
    """

    model_config = ConfigDict(extra="ignore")

    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0
    total_events: int = 0

    @property
    def total_predictions(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.false_negative
            + self.true_negative
        )


# ---------------------------------------------------------------------------
# Tuning metrics (the 4 KPIs)
# ---------------------------------------------------------------------------


class TuningMetrics(BaseModel):
    """The 4 key metrics for evaluating KhaiNet vs Darktrace."""

    model_config = ConfigDict(extra="ignore")

    coverage: float = 0.0  # TP_KhaiNet / total_incidentes_DT (%)
    precision: float = 0.0  # TP / (TP + FP) (%)
    advantage: int = 0  # incidents KhaiNet detects that DT doesn't
    mttd_khainet_seconds: float = 0.0
    mttd_darktrace_seconds: float = 0.0
    mttd_diff_pct: float = 0.0  # percentage difference
    confusion_matrix: ConfusionMatrix = Field(default_factory=ConfusionMatrix)
    gap_analysis: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Experiment run
# ---------------------------------------------------------------------------


class ExperimentRun(BaseModel):
    """A single experiment run record for versioning and comparison."""

    model_config = ConfigDict(extra="ignore")

    run_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    config_hash: str = ""
    dataset_hash: str = ""
    model_results: list[TuningResult] = Field(default_factory=list)
    fusion_result: FusionResult | None = None
    metrics: TuningMetrics | None = None
    notes: str = ""

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)


# ---------------------------------------------------------------------------
# Drift result
# ---------------------------------------------------------------------------


class DriftResult(BaseModel):
    """Result of a single drift metric for one model."""

    model_config = ConfigDict(extra="ignore")

    metric_name: str  # psi | ks | wasserstein
    value: float
    threshold: float
    is_drifted: bool
    severity: str = "none"  # none|low|medium|high


# ===========================================================================
# Auto-labeling system — multi-source weak supervision + active learning
# ===========================================================================


# ---------------------------------------------------------------------------
# Source-specific alert models (raw input → model)
# ---------------------------------------------------------------------------


class SuricataAlert(BaseModel):
    """An alert parsed from Suricata's EVE JSON output.

    Suricata generates alerts when its signature rules (ET rules, custom)
    match network traffic. These are high-confidence positive labels.
    """

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "tcp"
    alert_signature: str = ""
    alert_category: str = ""
    alert_severity: int = 3  # Suricata: 1=high, 2=medium, 3=low
    rule_id: str = ""
    mitre_attack_id: str | None = None  # e.g. "T1041"
    flow_id: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class WazuhAlert(BaseModel):
    """An alert from Wazuh (HIDS — Host Intrusion Detection System).

    Wazuh monitors endpoints: file integrity, rootkit detection, log analysis,
    vulnerability detection, and compliance checking.
    """

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    agent_id: str = ""
    agent_name: str = ""
    src_ip: str = ""  # pseudonymized hash (may be empty for host-only events)
    dst_ip: str = ""
    rule_id: str = ""
    rule_level: int = 3  # Wazuh: 0-15, ≥7 is high severity
    rule_description: str = ""
    rule_groups: list[str] = Field(default_factory=list)
    event_type: str = ""  # syscheck, rootcheck, auth, etc.
    full_log: str = ""

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class MISPEvent(BaseModel):
    """A threat intelligence indicator from MISP (Malware Information Sharing Platform).

    MISP provides IOCs (Indicators of Compromise): malicious IPs, domains,
    file hashes, etc. When a network event matches a MISP IOC, it's a
    high-confidence positive label.
    """

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    src_ip: str  # pseudonymized hash of the matched IP
    dst_ip: str = ""  # pseudonymized hash (may be empty)
    ioc_type: str = ""  # ip-dst, ip-src, domain, url, md5, sha256
    ioc_value: str = ""  # the actual indicator (pseudonymized)
    event_id: str = ""
    event_info: str = ""  # description of the threat
    threat_level: int = 2  # MISP: 1=high, 2=medium, 3=low, 4=undefined
    tags: list[str] = Field(default_factory=list)
    mitre_attack_id: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class BrainCorrelation(BaseModel):
    """A correlation produced by the Brain component.

    Brain correlates multiple anomaly events across models and maps them to
    MITRE ATT&CK tactics/techniques. These are medium-confidence positive
    labels — Brain identifies patterns, but doesn't have ground truth.
    """

    model_config = ConfigDict(extra="ignore")

    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    src_ip: str  # pseudonymized hash
    dst_ip: str = ""  # pseudonymized hash
    mitre_tactic: str = ""  # e.g. "Exfiltration"
    mitre_technique: str = ""  # e.g. "T1041 - Exfiltration Over C2 Channel"
    mitre_attack_id: str = ""  # e.g. "T1041"
    contributing_events: list[str] = Field(default_factory=list)  # event_ids
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    narrative: str = ""  # Brain's natural-language explanation
    models_involved: list[str] = Field(default_factory=list)  # IF, AE, HMM

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class AnalystFeedback(BaseModel):
    """A label provided by a human analyst via active learning.

    The analyst reviews events selected by the active learning module and
    confirms whether they are true positives or false positives. These are
    the highest-confidence labels (ground truth from human judgment).
    """

    model_config = ConfigDict(extra="ignore")

    feedback_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    src_ip: str  # pseudonymized hash
    dst_ip: str  # pseudonymized hash
    label: bool  # True=confirmed anomaly, False=confirmed normal
    analyst_id: str = ""
    event_id: str = ""  # the event being labeled
    notes: str = ""
    mitre_attack_id: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


# ---------------------------------------------------------------------------
# Weak supervision models
# ---------------------------------------------------------------------------


class WeakLabel(BaseModel):
    """A single label vote from one labeling source (labelling function).

    Each source produces a WeakLabel with:
    - ``label``: True (anomaly), False (normal), or None (abstain)
    - ``confidence``: how confident this source is about this specific label
    - ``source``: which labeling function produced this vote
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    source: str  # suricata, wazuh, misp, brain, analyst, darktrace
    label: bool | None = None  # None = abstain (no opinion)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    event_type: str | None = None
    mitre_attack_id: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class ConsensusLabel(BaseModel):
    """A label produced by combining multiple WeakLabels via weak supervision.

    The weak supervisor aggregates votes from multiple sources and produces
    a final label with aggregated confidence. This replaces the single-source
    SupervisedLabel when Darktrace is not available.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    src_ip: str
    dst_ip: str
    label: bool
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = "weak_supervision"
    contributing_sources: list[str] = Field(default_factory=list)
    vote_breakdown: dict[str, Any] = Field(default_factory=dict)
    # Number of sources that voted True / False / Abstain
    votes_positive: int = 0
    votes_negative: int = 0
    votes_abstain: int = 0
    event_type: str | None = None
    mitre_attack_id: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()

    def to_supervised_label(self) -> SupervisedLabel:
        """Convert to a SupervisedLabel for compatibility with the existing pipeline."""
        return SupervisedLabel(
            event_id=self.event_id,
            timestamp=self.timestamp,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            label=self.label,
            source=self.source,
            confidence=self.confidence,
            event_type=self.event_type,
        )


# ---------------------------------------------------------------------------
# Active learning models
# ---------------------------------------------------------------------------


class ActiveLearningQuery(BaseModel):
    """A query for the analyst to review an uncertain event.

    The active learning module selects events where the system is most
    uncertain (near the decision threshold, or where models disagree) and
    presents them to the analyst for confirmation.
    """

    model_config = ConfigDict(extra="ignore")

    query_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    model_scores: dict[str, float] = Field(default_factory=dict)
    unified_score: float = Field(ge=0.0, le=1.0)
    current_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    selection_reason: str = ""  # uncertainty, disagreement, diversity
    uncertainty_score: float = Field(ge=0.0, le=1.0)
    suggested_label: bool | None = None
    mitre_attack_id: str | None = None
    event_type: str | None = None
    # Context for the analyst
    context: dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"  # pending, confirmed, rejected, skipped

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)

    @property
    def ts_epoch(self) -> float:
        return self.timestamp.timestamp()


class ActiveLearningBatch(BaseModel):
    """A batch of active learning queries for the analyst to review.

    The active learning module selects a batch of the most informative
    events and packages them for review. The analyst's feedback is then
    fed back as AnalystFeedback labels.
    """

    model_config = ConfigDict(extra="ignore")

    batch_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    queries: list[ActiveLearningQuery] = Field(default_factory=list)
    strategy: str = "uncertainty"  # uncertainty, disagreement, diversity, hybrid
    batch_size: int = 0
    model_thresholds: dict[str, float] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        return _parse_timestamp(v)


# ---------------------------------------------------------------------------
# Label source configuration
# ---------------------------------------------------------------------------


class LabelSourceConfig(BaseModel):
    """Configuration for a single label source.

    Each source has:
    - ``enabled``: whether to use this source
    - ``weight``: default weight in the weak supervisor (can be learned)
    - ``min_confidence``: minimum confidence to include a label from this source
    - ``params``: source-specific parameters
    """

    model_config = ConfigDict(extra="ignore")

    name: str  # suricata, wazuh, misp, brain, analyst, darktrace
    enabled: bool = True
    weight: float = Field(default=1.0, ge=0.0, le=10.0)
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    params: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Weighted aligned event (extends AlignedEvent with confidence-weighted label)
# ---------------------------------------------------------------------------


class WeightedAlignedEvent(AlignedEvent):
    """An aligned event with confidence-weighted label for threshold tuning.

    Extends AlignedEvent with:
    - ``label_confidence``: confidence of the label (0-1), from weak supervision
    - ``label_source``: which source(s) produced the label
    """

    label_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    label_source: str = "darktrace"
    contributing_sources: list[str] = Field(default_factory=list)
