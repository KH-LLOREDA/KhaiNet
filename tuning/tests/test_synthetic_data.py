"""Tests for the synthetic data generator."""

from __future__ import annotations

from datetime import datetime, timezone

from src.models import AlignedEvent, DarktraceAlert, ModelScore
from src.synthetic_data import (
    generate_aligned_dataset,
    generate_darktrace_alerts,
    generate_multi_model_scores,
    generate_synthetic_events,
)


class TestGenerateSyntheticEvents:
    def test_basic_generation(self):
        scores, labels = generate_synthetic_events(
            n_events=100, anomaly_ratio=0.1, seed=42
        )
        assert len(scores) == 100
        assert len(labels) == 100
        assert len(scores) == len(labels)

    def test_anomaly_ratio(self):
        scores, labels = generate_synthetic_events(
            n_events=1000, anomaly_ratio=0.05, seed=42
        )
        n_anomalies = sum(labels)
        # Should be approximately 5% (50)
        assert 30 <= n_anomalies <= 70

    def test_reproducible_with_seed(self):
        s1, l1 = generate_synthetic_events(n_events=50, seed=123)
        s2, l2 = generate_synthetic_events(n_events=50, seed=123)
        assert [s.score for s in s1] == [s.score for s in s2]
        assert l1 == l2

    def test_different_seeds_differ(self):
        s1, _ = generate_synthetic_events(n_events=50, seed=1)
        s2, _ = generate_synthetic_events(n_events=50, seed=2)
        assert [s.score for s in s1] != [s.score for s in s2]

    def test_scores_in_range(self):
        scores, _ = generate_synthetic_events(n_events=100, seed=42)
        for s in scores:
            assert 0.0 <= s.score <= 1.0

    def test_ips_pseudonymized(self):
        scores, _ = generate_synthetic_events(n_events=10, seed=42)
        for s in scores:
            # SHA-256 hex = 64 chars
            assert len(s.src_ip) == 64
            assert len(s.dst_ip) == 64

    def test_timestamps_valid(self):
        scores, _ = generate_synthetic_events(n_events=10, seed=42)
        for s in scores:
            assert s.timestamp.tzinfo is not None

    def test_anomaly_scores_higher(self):
        """Anomaly scores should be higher than normal scores on average."""
        scores, labels = generate_synthetic_events(
            n_events=500, anomaly_ratio=0.1, seed=42
        )
        anomaly_scores = [s.score for s, l in zip(scores, labels) if l]
        normal_scores = [s.score for s, l in zip(scores, labels) if not l]
        assert np.mean(anomaly_scores) > np.mean(normal_scores)


class TestGenerateDarktraceAlerts:
    def test_basic_generation(self):
        alerts = generate_darktrace_alerts(n_alerts=20, seed=42)
        assert len(alerts) == 20
        for a in alerts:
            assert isinstance(a, DarktraceAlert)
            assert a.category in (
                "exfiltration",
                "c2_beaconing",
                "lateral_movement",
                "dns_tunneling",
                "scan",
            )
            assert a.severity in ("low", "medium", "high", "critical")

    def test_reproducible(self):
        a1 = generate_darktrace_alerts(n_alerts=10, seed=99)
        a2 = generate_darktrace_alerts(n_alerts=10, seed=99)
        assert [a.alert_id for a in a1] == [a.alert_id for a in a2]

    def test_ips_pseudonymized(self):
        alerts = generate_darktrace_alerts(n_alerts=5, seed=42)
        for a in alerts:
            assert len(a.src_ip) == 64
            assert len(a.dst_ip) == 64


class TestGenerateAlignedDataset:
    def test_basic_generation(self):
        aligned = generate_aligned_dataset(n_events=100, anomaly_ratio=0.1, seed=42)
        assert len(aligned) == 100
        for ae in aligned:
            assert isinstance(ae, AlignedEvent)

    def test_some_matched(self):
        aligned = generate_aligned_dataset(n_events=200, anomaly_ratio=0.1, seed=42)
        matched = sum(1 for ae in aligned if ae.matched_label_id is not None)
        # Some events should be matched (anomalies with labels)
        assert matched > 0

    def test_some_unmatched(self):
        aligned = generate_aligned_dataset(n_events=200, anomaly_ratio=0.1, seed=42)
        unmatched = sum(1 for ae in aligned if ae.matched_label_id is None)
        # Normal events should be unmatched
        assert unmatched > 0


class TestGenerateMultiModelScores:
    def test_three_models(self):
        scores, labels = generate_multi_model_scores(
            n_events=50, anomaly_ratio=0.1, seed=42
        )
        assert len(scores) == 3
        assert "isolation_forest" in scores
        assert "autoencoder" in scores
        assert "hmm" in scores

    def test_consistent_lengths(self):
        scores, labels = generate_multi_model_scores(n_events=50, seed=42)
        for model in scores:
            assert len(scores[model]) == 50
        assert len(labels) == 50

    def test_scores_in_range(self):
        scores, _ = generate_multi_model_scores(n_events=50, seed=42)
        for model in scores:
            for s in scores[model]:
                assert 0.0 <= s <= 1.0


# Need numpy for mean comparison
import numpy as np  # noqa: E402
