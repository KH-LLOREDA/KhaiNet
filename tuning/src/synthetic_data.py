"""Synthetic data generator for mock mode and testing.

Generates realistic network events, model scores, and Darktrace alerts
without requiring real infrastructure. All IPs are pseudonymized SHA-256 hashes.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
import structlog

from src.models import (
    AlignedEvent,
    DarktraceAlert,
    ModelScore,
    SupervisedLabel,
    AnalystFeedback,
    BrainCorrelation,
    MISPEvent,
    SuricataAlert,
    WazuhAlert,
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


# ===========================================================================
# Auto-labeling synthetic data generators
# ===========================================================================

# MITRE ATT&CK tactics for Brain correlations
MITRE_TACTICS = [
    ("Reconnaissance", "T1595", "Active Scanning"),
    ("Command and Control", "T1041", "Exfiltration Over C2 Channel"),
    ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("Lateral Movement", "T1021", "Remote Services"),
    ("Credential Access", "T1110", "Brute Force"),
    ("Discovery", "T1046", "Network Service Discovery"),
]

# MISP IOC types and tags
MISP_IOC_TYPES = ["ip-dst", "ip-src", "domain", "url"]
MISP_TAGS = ["c2", "botnet", "exfiltration", "scan", "recon", "malware"]

# Wazuh rule groups
WAZUH_GROUPS = ["syscheck", "rootcheck", "auth", "web", "malware"]

# Suricata alert categories
SURICATA_CATEGORIES = [
    "Trojan Activity",
    "Attempted Administrator Privilege Gain",
    "Data Exfiltration",
    "DNS Tunneling",
    "Network Scan",
    "Malware Command and Control Activity Detected",
]


def generate_suricata_alerts(
    n_alerts: int = 30,
    seed: int = 42,
    base_events: list[ModelScore] | None = None,
) -> list[SuricataAlert]:
    """Generate synthetic Suricata EVE JSON alerts.

    If ``base_events`` is provided, alerts are generated to match those events
    (same IPs, timestamps within jitter). Otherwise, random alerts are generated.

    Args:
        n_alerts: Number of alerts to generate.
        seed: Random seed.
        base_events: Optional model events to match alerts to.

    Returns:
        List of SuricataAlert objects.
    """
    rng = random.Random(seed)
    alerts: list[SuricataAlert] = []

    for i in range(n_alerts):
        if base_events and i < len(base_events):
            evt = base_events[i]
            ts = evt.timestamp + timedelta(seconds=rng.uniform(-5, 5))
            src_ip = evt.src_ip
            dst_ip = evt.dst_ip
        else:
            ts = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(
                seconds=rng.randint(0, 86400)
            )
            src_ip = _random_ip(rng, "sur-src")
            dst_ip = _random_ip(rng, "sur-dst")

        category = rng.choice(SURICATA_CATEGORIES)
        severity = rng.choices([1, 2, 3], weights=[30, 50, 20], k=1)[0]
        mitre_id = rng.choice(["T1041", "T1595", "T1021", "T1046", None])

        alerts.append(
            SuricataAlert(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=rng.randint(1024, 65535),
                dst_port=rng.choice([22, 53, 80, 443, 445, 3389, 8080]),
                protocol=rng.choice(["tcp", "udp"]),
                alert_signature=f"ET POLICY {category} - Rule {i}",
                alert_category=category,
                alert_severity=severity,
                rule_id=f"sid:{2100000 + i}",
                mitre_attack_id=mitre_id,
                flow_id=f"flow-{i}",
            )
        )

    log.debug("suricata_alerts_generated", n_alerts=len(alerts))
    return alerts


def generate_wazuh_alerts(
    n_alerts: int = 20,
    seed: int = 42,
    base_events: list[ModelScore] | None = None,
) -> list[WazuhAlert]:
    """Generate synthetic Wazuh HIDS alerts.

    Args:
        n_alerts: Number of alerts to generate.
        seed: Random seed.
        base_events: Optional model events to match alerts to.

    Returns:
        List of WazuhAlert objects.
    """
    rng = random.Random(seed)
    alerts: list[WazuhAlert] = []

    for i in range(n_alerts):
        if base_events and i < len(base_events):
            evt = base_events[i]
            ts = evt.timestamp + timedelta(seconds=rng.uniform(-10, 10))
            src_ip = evt.src_ip
            dst_ip = evt.dst_ip
        else:
            ts = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(
                seconds=rng.randint(0, 86400)
            )
            src_ip = _random_ip(rng, "waz-src") if rng.random() > 0.3 else ""
            dst_ip = _random_ip(rng, "waz-dst") if src_ip else ""

        rule_level = rng.choices(
            [3, 6, 7, 9, 12, 14], weights=[10, 20, 30, 25, 10, 5], k=1
        )[0]
        groups = rng.sample(WAZUH_GROUPS, k=rng.randint(1, 3))

        alerts.append(
            WazuhAlert(
                timestamp=ts,
                agent_id=str(rng.randint(1, 50)),
                agent_name=f"agent-{i}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                rule_id=f"rule-{500000 + i}",
                rule_level=rule_level,
                rule_description=f"Wazuh alert {i}: {' '.join(groups)}",
                rule_groups=groups,
                event_type=groups[0] if groups else "unknown",
                full_log=f"Log entry for alert {i}",
            )
        )

    log.debug("wazuh_alerts_generated", n_alerts=len(alerts))
    return alerts


def generate_misp_events(
    n_events: int = 25,
    seed: int = 42,
    base_events: list[ModelScore] | None = None,
) -> list[MISPEvent]:
    """Generate synthetic MISP threat intelligence events.

    Args:
        n_events: Number of events to generate.
        seed: Random seed.
        base_events: Optional model events to match IOCs to.

    Returns:
        List of MISPEvent objects.
    """
    rng = random.Random(seed)
    events: list[MISPEvent] = []

    for i in range(n_events):
        if base_events and i < len(base_events):
            evt = base_events[i]
            ts = evt.timestamp + timedelta(seconds=rng.uniform(-5, 5))
            src_ip = evt.src_ip
            dst_ip = evt.dst_ip
        else:
            ts = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(
                seconds=rng.randint(0, 86400)
            )
            src_ip = _random_ip(rng, "misp-src")
            dst_ip = _random_ip(rng, "misp-dst")

        threat_level = rng.choices([1, 2, 3, 4], weights=[30, 40, 20, 10], k=1)[0]
        ioc_type = rng.choice(MISP_IOC_TYPES)
        tags = rng.sample(MISP_TAGS, k=rng.randint(1, 3))
        mitre_id = rng.choice(["T1041", "T1595", "T1021", None])

        events.append(
            MISPEvent(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                ioc_type=ioc_type,
                ioc_value=_pseudonymize_ip(f"ioc-{i}"),
                event_id=f"misp-{i}",
                event_info=f"Threat intel event {i}: {', '.join(tags)}",
                threat_level=threat_level,
                tags=tags,
                mitre_attack_id=mitre_id,
            )
        )

    log.debug("misp_events_generated", n_events=len(events))
    return events


def generate_brain_correlations(
    n_correlations: int = 15,
    seed: int = 42,
    base_events: list[ModelScore] | None = None,
) -> list[BrainCorrelation]:
    """Generate synthetic Brain correlations.

    Args:
        n_correlations: Number of correlations to generate.
        seed: Random seed.
        base_events: Optional model events to match correlations to.

    Returns:
        List of BrainCorrelation objects.
    """
    rng = random.Random(seed)
    correlations: list[BrainCorrelation] = []

    for i in range(n_correlations):
        if base_events and i < len(base_events):
            evt = base_events[i]
            ts = evt.timestamp + timedelta(seconds=rng.uniform(-3, 3))
            src_ip = evt.src_ip
            dst_ip = evt.dst_ip
        else:
            ts = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(
                seconds=rng.randint(0, 86400)
            )
            src_ip = _random_ip(rng, "brain-src")
            dst_ip = _random_ip(rng, "brain-dst")

        tactic, attack_id, technique = rng.choice(MITRE_TACTICS)
        confidence = rng.uniform(0.4, 0.9)
        n_contributing = rng.randint(2, 5)
        models_involved = rng.sample(MODEL_NAMES, k=rng.randint(1, 3))

        correlations.append(
            BrainCorrelation(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                mitre_tactic=tactic,
                mitre_technique=f"{attack_id} - {technique}",
                mitre_attack_id=attack_id,
                contributing_events=[f"evt-{i}-{j}" for j in range(n_contributing)],
                confidence=confidence,
                narrative=f"Brain detected {tactic} activity: {technique}",
                models_involved=models_involved,
            )
        )

    log.debug("brain_correlations_generated", n_correlations=len(correlations))
    return correlations


def generate_analyst_feedback(
    n_feedback: int = 10,
    seed: int = 42,
    base_events: list[ModelScore] | None = None,
    positive_ratio: float = 0.6,
) -> list[AnalystFeedback]:
    """Generate synthetic analyst feedback (active learning labels).

    Args:
        n_feedback: Number of feedback entries to generate.
        seed: Random seed.
        base_events: Optional model events to label.
        positive_ratio: Fraction of labels that are True (anomaly confirmed).

    Returns:
        List of AnalystFeedback objects.
    """
    rng = random.Random(seed)
    feedbacks: list[AnalystFeedback] = []

    for i in range(n_feedback):
        if base_events and i < len(base_events):
            evt = base_events[i]
            ts = evt.timestamp
            src_ip = evt.src_ip
            dst_ip = evt.dst_ip
            event_id = evt.event_id
        else:
            ts = datetime(2026, 7, 1, tzinfo=timezone.utc) + timedelta(
                seconds=rng.randint(0, 86400)
            )
            src_ip = _random_ip(rng, "analyst-src")
            dst_ip = _random_ip(rng, "analyst-dst")
            event_id = f"evt-review-{i}"

        label = rng.random() < positive_ratio
        mitre_id = rng.choice(["T1041", "T1595", "T1021", None]) if label else None

        feedbacks.append(
            AnalystFeedback(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                label=label,
                analyst_id=f"analyst-{rng.randint(1, 5)}",
                event_id=event_id,
                notes="Confirmed anomaly" if label else "False positive",
                mitre_attack_id=mitre_id,
            )
        )

    log.debug(
        "analyst_feedback_generated",
        n_feedback=len(feedbacks),
        n_positive=sum(1 for f in feedbacks if f.label),
    )
    return feedbacks


def generate_auto_labeling_dataset(
    n_events: int = 500,
    anomaly_ratio: float = 0.05,
    seed: int = 42,
) -> dict[str, Any]:
    """Generate a complete auto-labeling dataset for testing.

    Produces:
    - Model events (scores from 3 models)
    - Suricata alerts (matching ~60% of anomalies)
    - Wazuh alerts (matching ~40% of anomalies)
    - MISP events (matching ~30% of anomalies)
    - Brain correlations (matching ~50% of anomalies)
    - Analyst feedback (matching ~20% of events, high confidence)
    - Ground truth labels (for validation)

    The sources have partial overlap — some anomalies are detected by
    multiple sources, some by only one, and some are missed by all
    (candidates for active learning).

    Args:
        n_events: Number of model events to generate.
        anomaly_ratio: Fraction of anomalies.
        seed: Random seed.

    Returns:
        Dict with keys: events, ground_truth, suricata, wazuh, misp,
        brain, analyst.
    """
    from src.synthetic_data import generate_synthetic_events

    rng = random.Random(seed)
    scores, ground_truth = generate_synthetic_events(n_events, anomaly_ratio, seed)

    # Separate anomaly and normal events
    anomaly_events = [s for s, l in zip(scores, ground_truth) if l]

    # Generate source data matching subsets of anomalies
    n_anomalies = len(anomaly_events)

    # Suricata: detects ~60% of anomalies
    suricata_base = anomaly_events[: int(n_anomalies * 0.6)]
    suricata_alerts = generate_suricata_alerts(
        n_alerts=len(suricata_base), seed=seed + 1, base_events=suricata_base
    )

    # Wazuh: detects ~40% of anomalies
    wazuh_base = anomaly_events[int(n_anomalies * 0.2) : int(n_anomalies * 0.6)]
    wazuh_alerts = generate_wazuh_alerts(
        n_alerts=len(wazuh_base), seed=seed + 2, base_events=wazuh_base
    )

    # MISP: detects ~30% of anomalies
    misp_base = anomaly_events[int(n_anomalies * 0.5) : int(n_anomalies * 0.8)]
    misp_events = generate_misp_events(
        n_events=len(misp_base), seed=seed + 3, base_events=misp_base
    )

    # Brain: detects ~50% of anomalies (with some false positives)
    brain_base = anomaly_events[int(n_anomalies * 0.1) : int(n_anomalies * 0.6)]
    brain_correlations = generate_brain_correlations(
        n_correlations=len(brain_base), seed=seed + 4, base_events=brain_base
    )

    # Analyst: has reviewed ~20% of all events (mix of anomalies and normals)
    reviewed_count = int(n_events * 0.2)
    reviewed_events = rng.sample(scores, min(reviewed_count, len(scores)))
    analyst_feedback = generate_analyst_feedback(
        n_feedback=len(reviewed_events),
        seed=seed + 5,
        base_events=reviewed_events,
        positive_ratio=anomaly_ratio,
    )

    dataset = {
        "events": scores,
        "ground_truth": ground_truth,
        "suricata": suricata_alerts,
        "wazuh": wazuh_alerts,
        "misp": misp_events,
        "brain": brain_correlations,
        "analyst": analyst_feedback,
    }

    log.info(
        "auto_labeling_dataset_generated",
        n_events=n_events,
        n_anomalies=n_anomalies,
        n_suricata=len(suricata_alerts),
        n_wazuh=len(wazuh_alerts),
        n_misp=len(misp_events),
        n_brain=len(brain_correlations),
        n_analyst=len(analyst_feedback),
    )
    return dataset
