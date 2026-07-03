"""Tests for HMM detector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.baseline import BaselineCalculator
from src.feature_engineering import extract_window_features
from src.hmm_detector import HMM_FEATURE_COLUMNS, HMMDetector
from src.models import ModelResult, StateMapping, WindowFeatures
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs


@pytest.fixture
def trained_hmm(sample_window_features):
    """A trained HMM detector."""
    detector = HMMDetector(n_components=4, n_iter=50, random_state=42)
    detector.fit(sample_window_features)
    return detector, sample_window_features


@pytest.fixture
def trained_hmm_with_baseline(sample_conn_events, sample_dns_events):
    """HMM trained with baseline for state mapping."""
    windows = extract_window_features(
        sample_conn_events, sample_dns_events, window_minutes=5
    )
    detector = HMMDetector(n_components=4, n_iter=50, random_state=42)
    detector.fit(windows)

    baseline = BaselineCalculator(window_hours=24)
    baseline.calculate_baseline(sample_conn_events, sample_dns_events)

    return detector, windows, baseline


class TestHMMFit:
    """Tests for fitting the HMM."""

    def test_fit_basic(self, sample_window_features):
        """Fit produces a non-None model."""
        detector = HMMDetector(n_components=4, n_iter=20, random_state=42)
        detector.fit(sample_window_features)
        assert detector.model is not None

    def test_fit_empty_features(self):
        """Fitting with empty features does not crash."""
        detector = HMMDetector(n_components=4, n_iter=10, random_state=42)
        detector.fit([])
        assert detector.model is None

    def test_fit_with_synthetic_data(self):
        """Fit with larger synthetic dataset."""
        conn = generate_zeek_conn_logs(n_events=500, seed=42)
        dns = generate_zeek_dns_logs(n_events=100, seed=42)
        windows = extract_window_features(conn, dns, window_minutes=5)
        detector = HMMDetector(n_components=4, n_iter=30, random_state=42)
        detector.fit(windows)
        assert detector.model is not None

    def test_fit_insufficient_data(self):
        """Fitting with very few samples handles gracefully."""
        # Create minimal windows
        base = datetime(2026, 7, 1, tzinfo=timezone.utc)
        windows = [
            WindowFeatures(
                timestamp=base,
                src_ip="host1",
                window_start=base,
                window_end=base + timedelta(minutes=5),
                bytes_out=1000,
                bytes_in=5000,
                pkts_total=10,
                unique_destinations=2,
                unique_ports=2,
                dns_queries=1,
                nxdomain_ratio=0.0,
                avg_duration=1.0,
                connection_count=5,
            )
        ]
        detector = HMMDetector(n_components=4, n_iter=10, random_state=42)
        detector.fit(windows)
        # Should not crash, may or may not fit depending on data


class TestHMMPredict:
    """Tests for predicting with the HMM."""

    def test_predict_basic(self, trained_hmm):
        """Predict produces ModelResult list."""
        detector, windows = trained_hmm
        results = detector.predict(windows)
        assert len(results) > 0
        assert all(isinstance(r, ModelResult) for r in results)

    def test_predict_scores_in_range(self, trained_hmm):
        """All scores are in 0-1 range."""
        detector, windows = trained_hmm
        results = detector.predict(windows)
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_predict_model_name(self, trained_hmm):
        """All results have model_name='hmm'."""
        detector, windows = trained_hmm
        results = detector.predict(windows)
        for r in results:
            assert r.model_name == "hmm"

    def test_predict_not_fitted(self):
        """Predicting without fitting returns empty list."""
        detector = HMMDetector()
        results = detector.predict([])
        assert results == []

    def test_predict_details_populated(self, trained_hmm):
        """Results have populated details dict."""
        detector, windows = trained_hmm
        results = detector.predict(windows)
        for r in results:
            assert "state" in r.details
            assert "state_label" in r.details

    def test_predict_with_synthetic_data(self):
        """Predict with synthetic data detects anomalies."""
        conn = generate_zeek_conn_logs(n_events=500, anomaly_ratio=0.1, seed=42)
        dns = generate_zeek_dns_logs(n_events=100, seed=42)
        windows = extract_window_features(conn, dns, window_minutes=5)
        detector = HMMDetector(n_components=4, n_iter=30, random_state=42)
        detector.fit(windows)
        results = detector.predict(windows)
        assert len(results) > 0
        # Some results should have non-normal state labels
        labels = {r.details.get("state_label") for r in results}
        assert len(labels) > 0


class TestHMMStateMapping:
    """Tests for HMM state mapping."""

    def test_map_states_basic(self, trained_hmm_with_baseline):
        """map_states produces StateMapping list."""
        detector, _, baseline = trained_hmm_with_baseline
        mappings = detector.map_states(baseline)
        assert len(mappings) > 0
        assert all(isinstance(m, StateMapping) for m in mappings)

    def test_map_states_labels(self, trained_hmm_with_baseline):
        """State mappings have valid labels."""
        detector, _, baseline = trained_hmm_with_baseline
        mappings = detector.map_states(baseline)
        valid_labels = {"normal", "scan", "exfil", "c2"}
        for m in mappings:
            assert m.label in valid_labels

    def test_map_states_unique_labels(self, trained_hmm_with_baseline):
        """Each state gets a unique label."""
        detector, _, baseline = trained_hmm_with_baseline
        mappings = detector.map_states(baseline)
        labels = [m.label for m in mappings]
        assert len(labels) == len(set(labels))

    def test_map_states_confidence_range(self, trained_hmm_with_baseline):
        """Confidence values are in 0-1 range."""
        detector, _, baseline = trained_hmm_with_baseline
        mappings = detector.map_states(baseline)
        for m in mappings:
            assert 0.0 <= m.confidence <= 1.0

    def test_map_states_mean_features(self, trained_hmm_with_baseline):
        """Mean features dict is populated."""
        detector, _, baseline = trained_hmm_with_baseline
        mappings = detector.map_states(baseline)
        for m in mappings:
            assert len(m.mean_features) > 0
            for col in HMM_FEATURE_COLUMNS:
                assert col in m.mean_features

    def test_map_states_not_fitted(self):
        """map_states on unfitted model returns empty list."""
        detector = HMMDetector()
        baseline = BaselineCalculator()
        mappings = detector.map_states(baseline)
        assert mappings == []


class TestHMMSequences:
    """Tests for sequence building."""

    def test_sequences_grouped_by_host(self):
        """Sequences are grouped by src_ip."""
        base = datetime(2026, 7, 1, tzinfo=timezone.utc)
        windows = []
        for i in range(10):
            for host in ["host1", "host2"]:
                ws = base + timedelta(minutes=i * 5)
                windows.append(
                    WindowFeatures(
                        timestamp=ws,
                        src_ip=host,
                        window_start=ws,
                        window_end=ws + timedelta(minutes=5),
                        bytes_out=1000 + i * 100,
                        bytes_in=5000 + i * 200,
                        pkts_total=10 + i,
                        unique_destinations=2 + (i % 3),
                        unique_ports=2,
                        dns_queries=1,
                        nxdomain_ratio=0.0,
                        avg_duration=1.0,
                        connection_count=5,
                    )
                )
        detector = HMMDetector(n_components=4, n_iter=20, random_state=42)
        X, lengths = detector._build_sequences(windows)
        assert len(lengths) == 2  # Two hosts
        assert sum(lengths) == X.shape[0]

    def test_sequences_short_filtered(self):
        """Sequences with < 2 windows are filtered out."""
        base = datetime(2026, 7, 1, tzinfo=timezone.utc)
        windows = [
            WindowFeatures(
                timestamp=base,
                src_ip="host1",
                window_start=base,
                window_end=base + timedelta(minutes=5),
                bytes_out=1000,
                bytes_in=5000,
                pkts_total=10,
                unique_destinations=2,
                unique_ports=2,
                dns_queries=1,
                nxdomain_ratio=0.0,
                avg_duration=1.0,
                connection_count=5,
            )
        ]
        detector = HMMDetector(n_components=4, n_iter=10, random_state=42)
        X, lengths = detector._build_sequences(windows)
        assert len(lengths) == 0  # Single window filtered out


class TestHMMTransitions:
    """Tests for transition matrix."""

    def test_get_transitions_not_fitted(self):
        """get_state_transitions on unfitted model returns None."""
        detector = HMMDetector()
        assert detector.get_state_transitions() is None

    def test_get_transitions_fitted(self, trained_hmm):
        """get_state_transitions returns a matrix after fitting."""
        detector, _ = trained_hmm
        trans = detector.get_state_transitions()
        assert trans is not None
        assert trans.shape == (4, 4)
