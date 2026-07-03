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
