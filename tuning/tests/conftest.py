"""Shared test fixtures for KhaiNet tuning tests.

All external dependencies (Darktrace API) are mocked so tests run without
real infrastructure. Uses synthetic data generators for realistic test data.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from src.models import (
    AlignedEvent,
    ConfusionMatrix,
    DarktraceAlert,
    ModelScore,
    SupervisedLabel,
)


# ---------------------------------------------------------------------------
# Time fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def now_utc() -> datetime:
    return datetime(2026, 7, 3, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def base_time() -> datetime:
    return datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# IP fixtures (pseudonymized hashes)
# ---------------------------------------------------------------------------


@pytest.fixture
def src_ip_a() -> str:
    return "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


@pytest.fixture
def dst_ip_a() -> str:
    return "f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8"


@pytest.fixture
def src_ip_b() -> str:
    return "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"


@pytest.fixture
def dst_ip_b() -> str:
    return "e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9"


# ---------------------------------------------------------------------------
# ModelScore fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_model_score(now_utc, src_ip_a, dst_ip_a) -> ModelScore:
    return ModelScore(
        event_id="evt-001",
        timestamp=now_utc,
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        model_name="isolation_forest",
        score=0.85,
        features={"bytes_out": 500000},
    )


@pytest.fixture
def sample_model_scores(now_utc, src_ip_a, dst_ip_a) -> list[ModelScore]:
    """10 model scores: 2 anomalies (high score) + 8 normal (low score)."""
    scores: list[ModelScore] = []
    for i in range(8):
        scores.append(
            ModelScore(
                event_id=f"evt-norm-{i}",
                timestamp=now_utc + timedelta(seconds=i * 10),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.1 + i * 0.02,
                features={},
            )
        )
    for i in range(2):
        scores.append(
            ModelScore(
                event_id=f"evt-anom-{i}",
                timestamp=now_utc + timedelta(seconds=100 + i * 10),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.90 + i * 0.03,
                features={},
            )
        )
    return scores


# ---------------------------------------------------------------------------
# SupervisedLabel fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_supervised_label(now_utc, src_ip_a, dst_ip_a) -> SupervisedLabel:
    return SupervisedLabel(
        event_id="label-001",
        timestamp=now_utc + timedelta(seconds=5),
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        label=True,
        darktrace_alert_id="dt-001",
        confidence=0.95,
        event_type="exfiltration",
    )


@pytest.fixture
def sample_supervised_labels(now_utc, src_ip_a, dst_ip_a) -> list[SupervisedLabel]:
    """Labels matching the sample_model_scores (2 anomalies)."""
    return [
        SupervisedLabel(
            event_id="label-anom-0",
            timestamp=now_utc + timedelta(seconds=102),
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
            darktrace_alert_id="dt-anom-0",
            confidence=0.95,
            event_type="exfiltration",
        ),
        SupervisedLabel(
            event_id="label-anom-1",
            timestamp=now_utc + timedelta(seconds=112),
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
            darktrace_alert_id="dt-anom-1",
            confidence=0.90,
            event_type="c2_beaconing",
        ),
    ]


# ---------------------------------------------------------------------------
# DarktraceAlert fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_darktrace_alert(now_utc, src_ip_a, dst_ip_a) -> DarktraceAlert:
    return DarktraceAlert(
        alert_id="dt-alert-001",
        timestamp=now_utc,
        model_name="isolation_forest",
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        category="exfiltration",
        severity="high",
        description="Data exfiltration detected",
        devices=[{"did": 1, "hostname": "SRV-DB-01"}],
        pbid="pbid-001",
        priority=3,
    )


@pytest.fixture
def sample_darktrace_alerts(
    src_ip_a, dst_ip_a, src_ip_b, dst_ip_b
) -> list[DarktraceAlert]:
    """5 Darktrace alerts with varying severity and categories."""
    base = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)
    categories = [
        "exfiltration",
        "c2_beaconing",
        "lateral_movement",
        "dns_tunneling",
        "scan",
    ]
    severities = ["critical", "high", "medium", "low", "medium"]
    ips = [(src_ip_a, dst_ip_a), (src_ip_b, dst_ip_b)]
    alerts: list[DarktraceAlert] = []
    for i in range(5):
        src, dst = ips[i % 2]
        alerts.append(
            DarktraceAlert(
                alert_id=f"dt-alert-{i}",
                timestamp=base + timedelta(minutes=i * 30),
                model_name="isolation_forest",
                src_ip=src,
                dst_ip=dst,
                src_port=50000 + i,
                dst_port=443,
                protocol="tcp",
                category=categories[i],
                severity=severities[i],
                description=f"Alert {i}: {categories[i]}",
                devices=[{"did": i + 1, "hostname": f"host-{i}"}],
                pbid=f"pbid-{i}",
                priority=i + 1,
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# AlignedEvent fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_aligned_events(
    sample_model_scores, sample_supervised_labels
) -> list[AlignedEvent]:
    """Pre-aligned events for threshold tuning tests."""
    from src.temporal_alignment import align_labels_to_events

    return align_labels_to_events(
        labels=sample_supervised_labels,
        events=sample_model_scores,
        window_seconds=60.0,
        jitter_seconds=30.0,
    )


# ---------------------------------------------------------------------------
# Score fixtures for fusion
# ---------------------------------------------------------------------------


@pytest.fixture
def fusion_scores() -> dict[str, list[float]]:
    """Scores from 3 models for 20 events (2 anomalies)."""
    scores: dict[str, list[float]] = {
        "isolation_forest": [],
        "autoencoder": [],
        "hmm": [],
    }
    # 18 normal events
    for i in range(18):
        for model in scores:
            scores[model].append(0.1 + (i % 5) * 0.02)
    # 2 anomaly events
    for i in range(2):
        for model in scores:
            scores[model].append(0.85 + i * 0.05)
    return scores


@pytest.fixture
def fusion_labels() -> list[bool]:
    """Labels matching fusion_scores: 18 normal + 2 anomalies."""
    return [False] * 18 + [True] * 2


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Test configuration matching tuning_config.yaml."""
    return {
        "darktrace": {
            "api_url": "https://darktrace.example.com",
            "api_token": "test-token",
            "mock_mode": True,
            "timeout_seconds": 5,
            "max_retries": 3,
            "rate_limit_per_second": 10,
        },
        "temporal_alignment": {
            "window_seconds": 60,
            "jitter_seconds": 30,
        },
        "cost_matrix": {
            "fn_cost": 10.0,
            "fp_cost": 1.0,
            "tp_benefit": 0.0,
            "tn_benefit": 0.0,
        },
        "threshold_tuning": {
            "optimization_metric": "cost_weighted",
            "min_threshold": 0.01,
            "max_threshold": 0.99,
            "threshold_steps": 100,
        },
        "score_fusion": {
            "method": "weighted_average",
            "default_weights": {
                "isolation_forest": 0.333,
                "autoencoder": 0.333,
                "hmm": 0.334,
            },
        },
        "metrics": {
            "targets": {
                "coverage": 90.0,
                "precision": 85.0,
                "advantage": 0,
                "latency_diff_pct": 30.0,
            }
        },
        "drift_check": {
            "psi_threshold": 0.25,
            "ks_pvalue_threshold": 0.05,
            "wasserstein_threshold": 0.1,
        },
        "experiment_tracker": {
            "output_dir": "./experiments",
        },
    }


# ---------------------------------------------------------------------------
# Cost matrix fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def default_cost_matrix():
    from src.cost_matrix import CostMatrix

    return CostMatrix(fn_cost=10.0, fp_cost=1.0)


# ---------------------------------------------------------------------------
# Confusion matrix fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_confusion_matrix() -> ConfusionMatrix:
    return ConfusionMatrix(
        true_positive=8,
        false_positive=2,
        false_negative=1,
        true_negative=89,
        total_events=100,
    )
