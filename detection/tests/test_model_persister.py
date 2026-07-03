"""Tests for model persister."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.autoencoder import AutoencoderDetector
from src.baseline import BaselineCalculator
from src.feature_engineering import normalize_features
from src.hmm_detector import HMMDetector
from src.isolation_forest import IsolationForestDetector
from src.model_persister import ModelPersister
from src.feature_engineering import extract_event_features, extract_window_features
from src.orchestrator import DetectionOrchestrator
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs


@pytest.fixture
def trained_models(sample_conn_events, sample_dns_events):
    """Train all models for persistence tests."""
    # Feature engineering
    event_features = extract_event_features(sample_conn_events, sample_dns_events)
    event_features, scaler = normalize_features(event_features)
    window_features = extract_window_features(
        sample_conn_events, sample_dns_events, window_minutes=5
    )

    # Train IF
    if_detector = IsolationForestDetector(
        n_estimators=20, random_state=42, threshold=0.6
    )
    if_detector.fit(event_features, scaler)

    # Train AE
    ae_detector = AutoencoderDetector(
        input_dim=len(event_features[0].normalized),
        hidden_dims=[16, 8],
        epochs=10,
        batch_size=8,
    )
    ae_detector.fit(event_features, scaler)

    # Train HMM
    hmm_detector = HMMDetector(n_components=4, n_iter=20, random_state=42)
    hmm_detector.fit(window_features)

    # Baseline
    baseline = BaselineCalculator(window_hours=24)
    baseline.calculate_baseline(sample_conn_events, sample_dns_events)

    # Map HMM states
    hmm_detector.map_states(baseline)

    return {
        "if_detector": if_detector,
        "ae_detector": ae_detector,
        "hmm_detector": hmm_detector,
        "baseline": baseline,
        "scaler": scaler,
        "event_features": event_features,
        "window_features": window_features,
    }


class TestSaveLoadIF:
    """Tests for Isolation Forest persistence."""

    def test_save_load_if_roundtrip(self, trained_models, tmp_path):
        """Save and load IF detector."""
        if_detector = trained_models["if_detector"]
        path = tmp_path / "if.joblib"
        ModelPersister.save_if(if_detector, path)
        assert path.exists()

        loaded = ModelPersister.load_if(path)
        assert loaded.model is not None
        assert loaded.threshold == if_detector.threshold
        assert loaded.n_estimators == if_detector.n_estimators

    def test_save_load_if_predictions_match(self, trained_models, tmp_path):
        """Loaded IF produces same predictions."""
        if_detector = trained_models["if_detector"]
        features = trained_models["event_features"]

        original_results = if_detector.predict(features)

        path = tmp_path / "if.joblib"
        ModelPersister.save_if(if_detector, path)
        loaded = ModelPersister.load_if(path)
        loaded_results = loaded.predict(features)

        assert len(original_results) == len(loaded_results)
        for orig, loaded_r in zip(original_results, loaded_results):
            assert abs(orig.score - loaded_r.score) < 1e-6


class TestSaveLoadAE:
    """Tests for Autoencoder persistence."""

    def test_save_load_ae_roundtrip(self, trained_models, tmp_path):
        """Save and load AE detector."""
        ae_detector = trained_models["ae_detector"]
        path = tmp_path / "ae.pt"
        ModelPersister.save_ae(ae_detector, path)
        assert path.exists()

        loaded = ModelPersister.load_ae(path, ae_detector.input_dim)
        assert loaded.model is not None
        assert loaded.threshold == ae_detector.threshold
        assert loaded.input_dim == ae_detector.input_dim

    def test_save_load_ae_errors_match(self, trained_models, tmp_path):
        """Loaded AE produces same reconstruction errors."""
        ae_detector = trained_models["ae_detector"]
        features = trained_models["event_features"]

        original_errors = ae_detector.get_reconstruction_errors(features)

        path = tmp_path / "ae.pt"
        ModelPersister.save_ae(ae_detector, path)
        loaded = ModelPersister.load_ae(path, ae_detector.input_dim)
        loaded_errors = loaded.get_reconstruction_errors(features)

        assert len(original_errors) == len(loaded_errors)
        for orig, loaded_e in zip(original_errors, loaded_errors):
            assert abs(orig - loaded_e) < 1e-4


class TestSaveLoadHMM:
    """Tests for HMM persistence."""

    def test_save_load_hmm_roundtrip(self, trained_models, tmp_path):
        """Save and load HMM detector."""
        hmm_detector = trained_models["hmm_detector"]
        path = tmp_path / "hmm.joblib"
        ModelPersister.save_hmm(hmm_detector, path)
        assert path.exists()

        loaded = ModelPersister.load_hmm(path)
        assert loaded.model is not None
        assert loaded.n_components == hmm_detector.n_components
        assert len(loaded.state_mappings) == len(hmm_detector.state_mappings)

    def test_save_load_hmm_state_mappings(self, trained_models, tmp_path):
        """Loaded HMM preserves state mappings."""
        hmm_detector = trained_models["hmm_detector"]
        path = tmp_path / "hmm.joblib"
        ModelPersister.save_hmm(hmm_detector, path)
        loaded = ModelPersister.load_hmm(path)

        for orig, loaded_m in zip(hmm_detector.state_mappings, loaded.state_mappings):
            assert orig.state_id == loaded_m.state_id
            assert orig.label == loaded_m.label


class TestSaveLoadBaseline:
    """Tests for baseline persistence."""

    def test_save_load_baseline_roundtrip(self, trained_models, tmp_path):
        """Save and load baseline."""
        baseline = trained_models["baseline"]
        path = tmp_path / "baseline.json"
        ModelPersister.save_baseline(baseline, path)
        assert path.exists()

        loaded = ModelPersister.load_baseline(path)
        assert loaded.window_hours == baseline.window_hours
        assert len(loaded.stats) == len(baseline.stats)

    def test_save_load_baseline_values(self, trained_models, tmp_path):
        """Loaded baseline preserves stat values."""
        baseline = trained_models["baseline"]
        path = tmp_path / "baseline.json"
        ModelPersister.save_baseline(baseline, path)
        loaded = ModelPersister.load_baseline(path)

        for orig, loaded_s in zip(baseline.stats, loaded.stats):
            assert orig.src_ip == loaded_s.src_ip
            assert orig.metric == loaded_s.metric
            assert orig.mean == loaded_s.mean
            assert orig.p99 == loaded_s.p99


class TestSaveLoadAll:
    """Tests for batch save/load."""

    def test_save_all_creates_files(self, trained_models, tmp_path):
        """save_all creates all expected files."""
        orchestrator = DetectionOrchestrator()
        orchestrator.if_detector = trained_models["if_detector"]
        orchestrator.ae_detector = trained_models["ae_detector"]
        orchestrator.hmm_detector = trained_models["hmm_detector"]
        orchestrator.baseline = trained_models["baseline"]
        orchestrator.scaler = trained_models["scaler"]
        orchestrator.input_dim = trained_models["ae_detector"].input_dim

        ModelPersister.save_all(orchestrator, tmp_path)

        assert (tmp_path / "isolation_forest.joblib").exists()
        assert (tmp_path / "autoencoder.pt").exists()
        assert (tmp_path / "hmm.joblib").exists()
        assert (tmp_path / "baseline.json").exists()
        assert (tmp_path / "scaler.joblib").exists()
        assert (tmp_path / "meta.json").exists()

    def test_load_all_returns_dict(self, trained_models, tmp_path):
        """load_all returns a dict with all models."""
        orchestrator = DetectionOrchestrator()
        orchestrator.if_detector = trained_models["if_detector"]
        orchestrator.ae_detector = trained_models["ae_detector"]
        orchestrator.hmm_detector = trained_models["hmm_detector"]
        orchestrator.baseline = trained_models["baseline"]
        orchestrator.scaler = trained_models["scaler"]
        orchestrator.input_dim = trained_models["ae_detector"].input_dim

        ModelPersister.save_all(orchestrator, tmp_path)
        loaded = ModelPersister.load_all(tmp_path)

        assert "if_detector" in loaded
        assert "ae_detector" in loaded
        assert "hmm_detector" in loaded
        assert "baseline" in loaded
        assert "scaler" in loaded
        assert "meta" in loaded

    def test_load_all_nonexistent_dir(self, tmp_path):
        """load_all on empty directory returns empty-ish dict."""
        loaded = ModelPersister.load_all(tmp_path)
        assert "meta" in loaded
