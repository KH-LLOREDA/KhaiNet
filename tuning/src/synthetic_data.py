"""Synthetic data generator for mock mode and testing.

Generates realistic network events, model scores, and Darktrace alerts
without requiring real infrastructure. All IPs are pseudonymized SHA-256 hashes.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

import numpy as np
import structlog

from src.models import (
    AlignedEvent,
    DarktraceAlert,
    ModelScore,
    SupervisedLabel,
)

log = structlog.get_logger()

# Model names matching the 3 KhaiNet detectors
MODEL_NAMES = ["isolation_forest", "autoencoder", "hmm"]

# Darktrace alert categories
ALERT_CATEGORIES = [
    "exfiltration",
    "c2_beaconing",
    "lateral_movement",
    "dns_tunneling",
    "scan",
]

ALERT_SEVERITIES = ["low", "medium", "high", "critical"]
ALERT_PROTOCOLS = ["tcp", "udp", "icmp"]


def _pseudonymize_ip(seed: str) -> str:
    """Pseudonymize an IP-like string into a SHA-256 hash (GDPR compliance)."""
    return hashlib.sha256(f"khainet-salt:{seed}".encode()).hexdigest()


def _random_ip(rng: random.Random, prefix: str = "host") -> str:
    """Generate a random pseudonymized IP hash."""
    return _pseudonymize_ip(f"{prefix}-{rng.randint(0, 10_000_000)}")


def generate_synthetic_events(
    n_events: int = 1000,
    anomaly_ratio: float = 0.01,
    seed: int = 42,
) -> tuple[list[ModelScore], list[bool]]:
    """Generate synthetic model scores and ground-truth labels.

    Anomalous events have higher scores (beta distribution skewed right),
    normal events have lower scores with noise. The ratio of anomalies
    is realistic (~1% by default).

    Args:
        n_events: Number of events to generate.
        anomaly_ratio: Fraction of events that are anomalies (0-1).
        seed: Random seed for reproducibility.

    Returns:
        Tuple of (list of ModelScore, list of bool labels).
    """
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    n_anomalies = max(1, int(n_events * anomaly_ratio))
    n_normal = n_events - n_anomalies

    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
    scores: list[ModelScore] = []
    labels: list[bool] = []

    # Generate anomalies first
    for i in range(n_anomalies):
        ts = base_time + timedelta(seconds=rng.randint(0, n_events * 10))
        src_ip = _random_ip(rng, "anom-src")
        dst_ip = _random_ip(rng, "anom-dst")
        label = True
        labels.append(label)
        # Each anomaly produces a score from all 3 models, but we return
        # one ModelScore per event (the "primary" model). For fusion tests,
        # generate_aligned_dataset handles multi-model scores.
        model_name = rng.choice(MODEL_NAMES)
        # Anomalies: high score (beta(5, 2) → mean ~0.71)
        score_val = float(np.clip(np_rng.beta(5, 2), 0.0, 1.0))
        scores.append(
            ModelScore(
                event_id=f"evt-anom-{i}",
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                model_name=model_name,
                score=score_val,
                features={"bytes_out": rng.randint(500_000, 5_000_000)},
            )
        )

    # Generate normal events
    for i in range(n_normal):
        ts = base_time + timedelta(seconds=rng.randint(0, n_events * 10))
        src_ip = _random_ip(rng, "norm-src")
        dst_ip = _random_ip(rng, "norm-dst")
        label = False
        labels.append(label)
        model_name = rng.choice(MODEL_NAMES)
        # Normal: low score (beta(2, 8) → mean ~0.20)
        score_val = float(np.clip(np_rng.beta(2, 8), 0.0, 1.0))
        scores.append(
            ModelScore(
                event_id=f"evt-norm-{i}",
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                model_name=model_name,
                score=score_val,
                features={"bytes_out": rng.randint(1_000, 50_000)},
            )
        )

    # Shuffle to interleave anomalies and normals
    combined = list(zip(scores, labels))
    rng.shuffle(combined)
    if combined:
        shuffled_scores, shuffled_labels = zip(*combined)
        scores = list(shuffled_scores)
        labels = list(shuffled_labels)
    else:
        scores = []
        labels = []
    log.debug(
        "synthetic_events_generated",
        n_events=len(scores),
        n_anomalies=n_anomalies,
        anomaly_ratio=anomaly_ratio,
    )
    return list(scores), list(labels)


def generate_darktrace_alerts(
    n_alerts: int = 50,
    seed: int = 42,
) -> list[DarktraceAlert]:
    """Generate realistic Darktrace alerts for mock mode.

    Categories: exfiltration, c2_beaconing, lateral_movement, dns_tunneling, scan.
    IPs are pseudonymized (SHA-256). Timestamps distributed over a 24h period.

    Args:
        n_alerts: Number of alerts to generate.
        seed: Random seed for reproducibility.

    Returns:
        List of DarktraceAlert objects.
    """
    rng = random.Random(seed)
    base_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
    alerts: list[DarktraceAlert] = []

    for i in range(n_alerts):
        ts = base_time + timedelta(seconds=rng.randint(0, 86400))
        category = rng.choice(ALERT_CATEGORIES)
        severity = rng.choices(ALERT_SEVERITIES, weights=[10, 40, 35, 15], k=1)[0]
        protocol = rng.choice(ALERT_PROTOCOLS)
        src_ip = _random_ip(rng, f"dt-src-{i}")
        dst_ip = _random_ip(rng, f"dt-dst-{i}")
        model_name = rng.choice(MODEL_NAMES)
        alerts.append(
            DarktraceAlert(
                alert_id=f"dt-alert-{i}",
                timestamp=ts,
                model_name=model_name,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([22, 53, 80, 443, 445, 3389, 8080]),
                protocol=protocol,
                category=category,
                severity=severity,
                description=f"Darktrace detected {category} from {src_ip[:8]} to {dst_ip[:8]}",
                devices=[
                    {"did": rng.randint(1, 500), "hostname": f"host-{i}"},
                ],
                pbid=f"pbid-{i}",
                priority=rng.randint(1, 5),
            )
        )

    log.debug("darktrace_alerts_generated", n_alerts=len(alerts))
    return alerts


def generate_aligned_dataset(
    n_events: int = 1000,
    anomaly_ratio: float = 0.01,
    seed: int = 42,
) -> list[AlignedEvent]:
    """Generate events + labels and align them temporally.

    This produces a ready-to-use dataset for threshold tuning: events with
    matching labels (some matched, some unmatched to simulate real conditions).

    Args:
        n_events: Number of events to generate.
        anomaly_ratio: Fraction of anomalies.
        seed: Random seed.

    Returns:
        List of AlignedEvent with scores and labels.
    """
    from src.temporal_alignment import align_labels_to_events

    rng = random.Random(seed)
    scores, labels = generate_synthetic_events(n_events, anomaly_ratio, seed)

    # Build supervised labels from the ground truth
    # For matched events: label timestamp ≈ event timestamp (within window)
    # For unmatched: some labels won't have corresponding events
    supervised_labels: list[SupervisedLabel] = []
    for score, is_anomaly in zip(scores, labels):
        # 90% of anomalies get a Darktrace label (coverage isn't perfect)
        # 5% of normals get a false Darktrace label (noise)
        if is_anomaly and rng.random() < 0.90:
            jitter = rng.uniform(-30, 30)
            supervised_labels.append(
                SupervisedLabel(
                    event_id=f"label-{score.event_id}",
                    timestamp=score.timestamp + timedelta(seconds=jitter),
                    src_ip=score.src_ip,
                    dst_ip=score.dst_ip,
                    label=True,
                    darktrace_alert_id=f"dt-{score.event_id}",
                    confidence=rng.uniform(0.8, 1.0),
                    event_type="anomaly",
                )
            )
        elif not is_anomaly and rng.random() < 0.05:
            jitter = rng.uniform(-30, 30)
            supervised_labels.append(
                SupervisedLabel(
                    event_id=f"label-{score.event_id}",
                    timestamp=score.timestamp + timedelta(seconds=jitter),
                    src_ip=score.src_ip,
                    dst_ip=score.dst_ip,
                    label=True,  # false positive from Darktrace
                    darktrace_alert_id=f"dt-fp-{score.event_id}",
                    confidence=rng.uniform(0.5, 0.7),
                    event_type="anomaly",
                )
            )

    aligned = align_labels_to_events(
        labels=supervised_labels,
        events=scores,
        window_seconds=60.0,
        jitter_seconds=30.0,
    )

    log.debug(
        "aligned_dataset_generated",
        n_events=len(aligned),
        n_labels=len(supervised_labels),
        n_matched=sum(1 for a in aligned if a.matched_label_id is not None),
    )
    return aligned


def generate_multi_model_scores(
    n_events: int = 1000,
    anomaly_ratio: float = 0.01,
    seed: int = 42,
) -> tuple[dict[str, list[float]], list[bool]]:
    """Generate scores from all 3 models for the same events.

    Useful for testing score fusion. Returns a dict mapping model name to
    list of scores, plus the ground-truth labels.

    Args:
        n_events: Number of events.
        anomaly_ratio: Fraction of anomalies.
        seed: Random seed.

    Returns:
        Tuple of (scores dict, labels list).
    """
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    n_anomalies = max(1, int(n_events * anomaly_ratio))
    n_normal = n_events - n_anomalies

    scores: dict[str, list[float]] = {m: [] for m in MODEL_NAMES}
    labels: list[bool] = []

    for i in range(n_anomalies):
        labels.append(True)
        for model in MODEL_NAMES:
            # Anomalies: high score with model-specific noise
            base = float(np_rng.beta(5, 2))
            noise = float(np_rng.normal(0, 0.05))
            scores[model].append(float(np.clip(base + noise, 0.0, 1.0)))

    for i in range(n_normal):
        labels.append(False)
        for model in MODEL_NAMES:
            base = float(np_rng.beta(2, 8))
            noise = float(np_rng.normal(0, 0.03))
            scores[model].append(float(np.clip(base + noise, 0.0, 1.0)))

    # Shuffle
    indices = list(range(n_events))
    rng.shuffle(indices)
    for model in MODEL_NAMES:
        scores[model] = [scores[model][j] for j in indices]
    labels = [labels[j] for j in indices]

    log.debug(
        "multi_model_scores_generated",
        n_events=n_events,
        models=MODEL_NAMES,
        n_anomalies=n_anomalies,
    )
    return scores, labels
