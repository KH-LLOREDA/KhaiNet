"""Integration tests for the full detection pipeline.

Tests the complete flow: generate synthetic data → parse → feature engineering
→ train 3 models → detect → baseline → verify results.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.baseline import BaselineCalculator
from src.feature_engineering import (
    extract_event_features,
    extract_window_features,
    normalize_features,
)
from src.hmm_detector import HMMDetector
from src.isolation_forest import IsolationForestDetector
from src.autoencoder import AutoencoderDetector
from src.models import ModelResult, ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL
from src.orchestrator import DetectionOrchestrator
from src.synthetic_data import (
    generate_all_logs,
    generate_zeek_conn_logs,
    generate_zeek_dns_logs,
    generate_zeek_http_logs,
    generate_zeek_ssl_logs,
    generate_zeek_log_string,
)
from src.zeek_parser import parse_zeek_log_from_string


@pytest.fixture
def integration_config():
    """Config for integration tests (fast but realistic)."""
    return {
        "isolation_forest": {
            "n_estimators": 30,
            "contamination": "auto",
            "random_state": 42,
            "threshold": 0.6,
        },
        "autoencoder": {
            "hidden_dims": [32, 16],
            "learning_rate": 0.01,
            "epochs": 15,
            "batch_size": 16,
            "threshold_percentile": 99,
            "random_state": 42,
        },
        "hmm": {
            "n_components": 4,
            "n_iter": 30,
            "covariance_type": "diag",
            "random_state": 42,
        },
        "baseline": {
            "window_hours": 24,
        },
        "feature_engineering": {
            "window_minutes": 5,
        },
        "orchestrator": {
            "mock_mode": True,
        },
    }


@pytest.fixture
def integration_data():
    """Generate synthetic data for integration tests."""
    return generate_all_logs(seed=42)


class TestFullPipeline:
    """End-to-end pipeline integration tests."""

    def test_generate_all_logs(self, integration_data):
        """generate_all_logs produces all 4 log types."""
        assert "conn" in integration_data
        assert "dns" in integration_data
        assert "http" in integration_data
        assert "ssl" in integration_data
        assert len(integration_data["conn"]) > 0
        assert len(integration_data["dns"]) > 0
        assert len(integration_data["http"]) > 0
        assert len(integration_data["ssl"]) > 0

    def test_full_pipeline_train_and_detect(self, integration_config, integration_data):
        """Full pipeline: train all models and detect anomalies."""
        orch = DetectionOrchestrator(integration_config)
        conn = integration_data["conn"]
        dns = integration_data["dns"]
        http = integration_data["http"]
        ssl = integration_data["ssl"]

        # Train
        summary = orch.train_all(conn, dns, http, ssl)
        assert summary["if_trained"] is True
        assert summary["ae_trained"] is True
        assert summary["hmm_trained"] is True
        assert summary["baseline_stats"] > 0

        # Detect
        results = orch.detect(conn, dns, http, ssl)
        assert len(results) > 0

        # Verify all 3 models produced results
        model_names = {r.model_name for r in results}
        assert "isolation_forest" in model_names
        assert "autoencoder" in model_names
        assert "hmm" in model_names

    def test_pipeline_scores_in_range(self, integration_config, integration_data):
        """All scores from the pipeline are in 0-1 range."""
        orch = DetectionOrchestrator(integration_config)
        orch.train_all(
            integration_data["conn"],
            integration_data["dns"],
            integration_data["http"],
            integration_data["ssl"],
        )
        results = orch.detect(
            integration_data["conn"],
            integration_data["dns"],
            integration_data["http"],
            integration_data["ssl"],
        )
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_pipeline_detects_anomalies(self, integration_config):
        """Pipeline detects anomalies in data with injected anomalies."""
        conn = generate_zeek_conn_logs(n_events=500, anomaly_ratio=0.1, seed=42)
        dns = generate_zeek_dns_logs(n_events=100, anomaly_ratio=0.1, seed=42)

        orch = DetectionOrchestrator(integration_config)
        orch.train_all(conn, dns)
        results = orch.detect(conn, dns)

        n_anomalies = sum(1 for r in results if r.is_anomaly)
        assert n_anomalies > 0

    def test_pipeline_save_load(self, integration_config, integration_data, tmp_path):
        """Pipeline models can be saved and loaded."""
        orch = DetectionOrchestrator(integration_config)
        orch.train_all(
            integration_data["conn"],
            integration_data["dns"],
        )

        model_dir = tmp_path / "models"
        orch.save_models(model_dir)

        new_orch = DetectionOrchestrator(integration_config)
        new_orch.load_models(model_dir)

        # Loaded models should produce predictions
        results = new_orch.detect(
            integration_data["conn"],
            integration_data["dns"],
        )
        assert len(results) > 0

    def test_pipeline_hmm_state_mapping(self, integration_config, integration_data):
        """HMM states are mapped to semantic labels after training."""
        orch = DetectionOrchestrator(integration_config)
        orch.train_all(
            integration_data["conn"],
            integration_data["dns"],
        )
        mappings = orch.hmm_detector.state_mappings
        assert len(mappings) > 0
        labels = {m.label for m in mappings}
        assert labels.issubset({"normal", "scan", "exfil", "c2"})

    def test_pipeline_baseline_comparison(self, integration_config, integration_data):
        """Baseline can compare events after training."""
        orch = DetectionOrchestrator(integration_config)
        orch.train_all(
            integration_data["conn"],
            integration_data["dns"],
        )
        # Compare a normal event
        normal_event = integration_data["conn"][0]
        result = orch.baseline.compare_to_baseline(normal_event)
        assert isinstance(result, dict)
        assert len(result) > 0


class TestPipelineComponents:
    """Tests for individual pipeline components in integration context."""

    def test_feature_engineering_to_if(self, integration_data):
        """Feature engineering → IF training works."""
        conn = integration_data["conn"]
        dns = integration_data["dns"]
        vectors = extract_event_features(conn, dns)
        vectors, scaler = normalize_features(vectors)

        detector = IsolationForestDetector(n_estimators=20, random_state=42)
        detector.fit(vectors, scaler)
        results = detector.predict(vectors)

        assert len(results) == len(vectors)
        assert all(0.0 <= r.score <= 1.0 for r in results)

    def test_feature_engineering_to_ae(self, integration_data):
        """Feature engineering → AE training works."""
        conn = integration_data["conn"]
        dns = integration_data["dns"]
        vectors = extract_event_features(conn, dns)
        vectors, scaler = normalize_features(vectors)

        detector = AutoencoderDetector(
            input_dim=len(vectors[0].normalized),
            hidden_dims=[32, 16],
            epochs=10,
            batch_size=16,
        )
        detector.fit(vectors, scaler)
        results = detector.predict(vectors)

        assert len(results) == len(vectors)
        assert all(0.0 <= r.score <= 1.0 for r in results)

    def test_feature_engineering_to_hmm(self, integration_data):
        """Feature engineering → HMM training works."""
        conn = integration_data["conn"]
        dns = integration_data["dns"]
        windows = extract_window_features(conn, dns, window_minutes=5)

        detector = HMMDetector(n_components=4, n_iter=30, random_state=42)
        detector.fit(windows)
        results = detector.predict(windows)

        assert len(results) > 0
        assert all(0.0 <= r.score <= 1.0 for r in results)

    def test_zeek_parser_to_feature_engineering(self):
        """Zeek parser → feature engineering works."""
        conn_str = generate_zeek_log_string("conn", n_events=100, seed=42)
        dns_str = generate_zeek_log_string("dns", n_events=50, seed=42)

        conn_events = parse_zeek_log_from_string(conn_str, ZeekConn)
        dns_events = parse_zeek_log_from_string(dns_str, ZeekDNS)

        vectors = extract_event_features(conn_events, dns_events)
        assert len(vectors) == len(conn_events)

    def test_baseline_to_hmm_mapping(self, integration_data):
        """Baseline → HMM state mapping works."""
        conn = integration_data["conn"]
        dns = integration_data["dns"]

        baseline = BaselineCalculator(window_hours=24)
        baseline.calculate_baseline(conn, dns)

        windows = extract_window_features(conn, dns, window_minutes=5)
        hmm = HMMDetector(n_components=4, n_iter=30, random_state=42)
        hmm.fit(windows)
        mappings = hmm.map_states(baseline)

        assert len(mappings) > 0
        labels = {m.label for m in mappings}
        assert labels.issubset({"normal", "scan", "exfil", "c2"})


class TestPipelineReproducibility:
    """Tests for reproducibility with fixed seeds."""

    def test_synthetic_data_reproducible(self):
        """Same seed produces same data."""
        data1 = generate_zeek_conn_logs(n_events=100, seed=42)
        data2 = generate_zeek_conn_logs(n_events=100, seed=42)
        assert len(data1) == len(data2)
        for e1, e2 in zip(data1, data2):
            assert e1.src_ip == e2.src_ip
            assert e1.dst_port == e2.dst_port

    def test_if_reproducible(self, integration_data):
        """IF with same seed produces same scores."""
        conn = integration_data["conn"][:200]
        dns = integration_data["dns"][:50]
        vectors = extract_event_features(conn, dns)
        vectors, scaler = normalize_features(vectors)

        det1 = IsolationForestDetector(n_estimators=20, random_state=42)
        det1.fit(vectors, scaler)
        r1 = det1.predict(vectors)

        det2 = IsolationForestDetector(n_estimators=20, random_state=42)
        det2.fit(vectors, scaler)
        r2 = det2.predict(vectors)

        for a, b in zip(r1, r2):
            assert abs(a.score - b.score) < 1e-6

    def test_ae_reproducible(self, integration_data):
        """AE with same seed produces similar errors."""
        conn = integration_data["conn"][:200]
        dns = integration_data["dns"][:50]
        vectors = extract_event_features(conn, dns)
        vectors, scaler = normalize_features(vectors)

        det1 = AutoencoderDetector(
            input_dim=len(vectors[0].normalized),
            hidden_dims=[16, 8],
            epochs=10,
            batch_size=8,
            random_state=42,
        )
        det1.fit(vectors, scaler)
        errors1 = det1.get_reconstruction_errors(vectors)

        det2 = AutoencoderDetector(
            input_dim=len(vectors[0].normalized),
            hidden_dims=[16, 8],
            epochs=10,
            batch_size=8,
            random_state=42,
        )
        det2.fit(vectors, scaler)
        errors2 = det2.get_reconstruction_errors(vectors)

        for a, b in zip(errors1, errors2):
            assert abs(a - b) < 1e-4


class TestPipelineEdgeCases:
    """Tests for edge cases in the pipeline."""

    def test_empty_pipeline(self, integration_config):
        """Pipeline handles empty input gracefully."""
        orch = DetectionOrchestrator(integration_config)
        summary = orch.train_all([], [], [], [])
        assert summary["n_conn_events"] == 0
        results = orch.detect([], [], [], [])
        assert results == []

    def test_single_event(self, integration_config):
        """Pipeline handles a single event."""
        conn = generate_zeek_conn_logs(n_events=50, seed=42)
        dns = generate_zeek_dns_logs(n_events=20, seed=42)
        orch = DetectionOrchestrator(integration_config)
        orch.train_all(conn, dns)
        # Detect on a subset
        results = orch.detect(conn[:5], dns[:5])
        # Should produce some results
        assert len(results) > 0

    def test_all_log_types_coordinated(self):
        """generate_all_logs produces coordinated data."""
        data = generate_all_logs(seed=99)
        # All timestamps should be within a reasonable range
        all_ts = [e.timestamp for e in data["conn"]]
        if all_ts:
            ts_range = max(all_ts) - min(all_ts)
            # Should span at least some time
            assert ts_range.total_seconds() > 0
