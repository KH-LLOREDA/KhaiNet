"""Tests for detection orchestrator."""

from __future__ import annotations

import pytest

from src.orchestrator import DetectionOrchestrator
from src.models import ModelResult
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs


@pytest.fixture
def trained_orchestrator(fast_config, sample_conn_events, sample_dns_events):
    """A trained orchestrator."""
    orch = DetectionOrchestrator(fast_config)
    orch.train_all(sample_conn_events, sample_dns_events)
    return orch


class TestOrchestratorInit:
    """Tests for orchestrator initialization."""

    def test_init_default_config(self):
        """Init with no config uses defaults."""
        orch = DetectionOrchestrator()
        assert orch.if_detector is not None
        assert orch.ae_detector is not None
        assert orch.hmm_detector is not None
        assert orch.baseline is not None
        assert orch.mock_mode is True

    def test_init_with_config(self, test_config):
        """Init with config applies settings."""
        orch = DetectionOrchestrator(test_config)
        assert orch.if_detector.n_estimators == 50
        assert orch.ae_detector.epochs == 20
        assert orch.hmm_detector.n_components == 4

    def test_init_mock_mode(self, test_config):
        """Mock mode is set from config."""
        orch = DetectionOrchestrator(test_config)
        assert orch.mock_mode is True


class TestOrchestratorTrainAll:
    """Tests for train_all."""

    def test_train_all_basic(self, fast_config, sample_conn_events, sample_dns_events):
        """train_all returns a summary dict."""
        orch = DetectionOrchestrator(fast_config)
        summary = orch.train_all(sample_conn_events, sample_dns_events)
        assert isinstance(summary, dict)
        assert summary["n_conn_events"] == len(sample_conn_events)
        assert summary["if_trained"] is True
        assert summary["ae_trained"] is True
        assert summary["hmm_trained"] is True

    def test_train_all_with_all_event_types(
        self,
        fast_config,
        sample_conn_events,
        sample_dns_events,
        sample_http_events,
        sample_ssl_events,
    ):
        """train_all works with all event types."""
        orch = DetectionOrchestrator(fast_config)
        summary = orch.train_all(
            sample_conn_events, sample_dns_events, sample_http_events, sample_ssl_events
        )
        assert summary["if_trained"] is True

    def test_train_all_empty_events(self, fast_config):
        """train_all with empty events doesn't crash."""
        orch = DetectionOrchestrator(fast_config)
        summary = orch.train_all([], [], [], [])
        assert summary["n_conn_events"] == 0
        assert summary["if_trained"] is False

    def test_train_all_baseline_calculated(self, trained_orchestrator):
        """Baseline is calculated after training."""
        assert len(trained_orchestrator.baseline.stats) > 0

    def test_train_all_hmm_states_mapped(self, trained_orchestrator):
        """HMM states are mapped after training."""
        assert len(trained_orchestrator.hmm_detector.state_mappings) > 0

    def test_train_all_scaler_fitted(self, trained_orchestrator):
        """Scaler is fitted after training."""
        assert trained_orchestrator.scaler is not None

    def test_train_all_with_synthetic_data(self, fast_config):
        """train_all with larger synthetic dataset."""
        conn = generate_zeek_conn_logs(n_events=300, seed=42)
        dns = generate_zeek_dns_logs(n_events=80, seed=42)
        orch = DetectionOrchestrator(fast_config)
        summary = orch.train_all(conn, dns)
        assert summary["if_trained"] is True
        assert summary["ae_trained"] is True
        assert summary["hmm_trained"] is True


class TestOrchestratorDetect:
    """Tests for detect."""

    def test_detect_basic(
        self, trained_orchestrator, sample_conn_events, sample_dns_events
    ):
        """detect produces ModelResult list."""
        results = trained_orchestrator.detect(sample_conn_events, sample_dns_events)
        assert len(results) > 0
        assert all(isinstance(r, ModelResult) for r in results)

    def test_detect_all_three_models(
        self, trained_orchestrator, sample_conn_events, sample_dns_events
    ):
        """detect produces results from all 3 models."""
        results = trained_orchestrator.detect(sample_conn_events, sample_dns_events)
        model_names = {r.model_name for r in results}
        assert "isolation_forest" in model_names
        assert "autoencoder" in model_names
        assert "hmm" in model_names

    def test_detect_scores_in_range(
        self, trained_orchestrator, sample_conn_events, sample_dns_events
    ):
        """All scores are in 0-1 range."""
        results = trained_orchestrator.detect(sample_conn_events, sample_dns_events)
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_detect_no_fusion(
        self, trained_orchestrator, sample_conn_events, sample_dns_events
    ):
        """detect does NOT fuse scores — returns individual results."""
        results = trained_orchestrator.detect(sample_conn_events, sample_dns_events)
        # Each result should have a single model_name, not a fused score
        for r in results:
            assert r.model_name in ("isolation_forest", "autoencoder", "hmm")

    def test_detect_not_trained(self, fast_config, sample_conn_events):
        """detect on untrained orchestrator returns empty list."""
        orch = DetectionOrchestrator(fast_config)
        results = orch.detect(sample_conn_events)
        assert results == []

    def test_detect_with_synthetic_data(self, fast_config):
        """Full detect with synthetic data."""
        conn = generate_zeek_conn_logs(n_events=300, seed=42)
        dns = generate_zeek_dns_logs(n_events=80, seed=42)
        orch = DetectionOrchestrator(fast_config)
        orch.train_all(conn, dns)
        results = orch.detect(conn, dns)
        assert len(results) > 0
        # Check we have results from all 3 models
        model_names = {r.model_name for r in results}
        assert len(model_names) == 3


class TestOrchestratorSaveLoad:
    """Tests for save_models and load_models."""

    def test_save_models(self, trained_orchestrator, tmp_path):
        """save_models creates files."""
        model_dir = tmp_path / "models"
        trained_orchestrator.save_models(model_dir)
        assert model_dir.exists()
        assert (model_dir / "meta.json").exists()

    def test_load_models(self, trained_orchestrator, tmp_path):
        """load_models restores models."""
        model_dir = tmp_path / "models"
        trained_orchestrator.save_models(model_dir)

        new_orch = DetectionOrchestrator()
        new_orch.load_models(model_dir)

        assert new_orch.if_detector.model is not None
        assert new_orch.ae_detector.model is not None
        assert new_orch.hmm_detector.model is not None
        assert len(new_orch.baseline.stats) > 0

    def test_save_load_predictions_match(
        self, trained_orchestrator, sample_conn_events, sample_dns_events, tmp_path
    ):
        """Predictions match after save/load."""
        original_results = trained_orchestrator.detect(
            sample_conn_events, sample_dns_events
        )

        model_dir = tmp_path / "models"
        trained_orchestrator.save_models(model_dir)

        new_orch = DetectionOrchestrator()
        new_orch.load_models(model_dir)
        loaded_results = new_orch.detect(sample_conn_events, sample_dns_events)

        assert len(original_results) == len(loaded_results)
