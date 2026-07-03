"""Tests for Autoencoder detector."""

from __future__ import annotations

import pytest

from src.autoencoder import AutoencoderDetector
from src.feature_engineering import extract_event_features, normalize_features
from src.models import ModelResult
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs


@pytest.fixture
def trained_ae(sample_feature_vectors):
    """A trained Autoencoder detector with small config for speed."""
    vectors, scaler = normalize_features(sample_feature_vectors)
    detector = AutoencoderDetector(
        input_dim=len(vectors[0].normalized),
        hidden_dims=[16, 8],
        lr=0.01,
        epochs=20,
        batch_size=8,
        random_state=42,
    )
    detector.fit(vectors, scaler)
    return detector, vectors


class TestAutoencoderFit:
    """Tests for fitting the Autoencoder."""

    def test_fit_basic(self, sample_feature_vectors):
        """Fit produces a non-None model."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        detector = AutoencoderDetector(
            input_dim=len(vectors[0].normalized),
            hidden_dims=[16, 8],
            epochs=10,
            batch_size=8,
        )
        detector.fit(vectors, scaler)
        assert detector.model is not None

    def test_fit_auto_normalizes(self, sample_feature_vectors):
        """Fit normalizes features if not already normalized."""
        detector = AutoencoderDetector(
            input_dim=17,
            hidden_dims=[16, 8],
            epochs=10,
            batch_size=8,
        )
        detector.fit(sample_feature_vectors)
        assert detector.model is not None
        assert detector.scaler is not None

    def test_fit_empty_features(self):
        """Fitting with empty features does not crash."""
        detector = AutoencoderDetector(input_dim=17, epochs=5)
        detector.fit([])
        assert detector.model is None

    def test_fit_sets_threshold(self, sample_feature_vectors):
        """Fit sets a reconstruction error threshold."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        detector = AutoencoderDetector(
            input_dim=len(vectors[0].normalized),
            hidden_dims=[16, 8],
            epochs=10,
            batch_size=8,
        )
        detector.fit(vectors, scaler)
        assert detector.threshold > 0

    def test_fit_tracks_losses(self, sample_feature_vectors):
        """Fit tracks training losses per epoch."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        detector = AutoencoderDetector(
            input_dim=len(vectors[0].normalized),
            hidden_dims=[16, 8],
            epochs=10,
            batch_size=8,
        )
        detector.fit(vectors, scaler)
        assert len(detector.training_losses) == 10

    def test_fit_with_synthetic_data(self):
        """Fit with larger synthetic dataset."""
        conn = generate_zeek_conn_logs(n_events=200, seed=42)
        dns = generate_zeek_dns_logs(n_events=50, seed=42)
        vectors = extract_event_features(conn, dns)
        detector = AutoencoderDetector(
            input_dim=17,
            hidden_dims=[32, 16],
            epochs=10,
            batch_size=16,
        )
        detector.fit(vectors)
        assert detector.model is not None


class TestAutoencoderPredict:
    """Tests for predicting with the Autoencoder."""

    def test_predict_basic(self, trained_ae):
        """Predict produces ModelResult list."""
        detector, vectors = trained_ae
        results = detector.predict(vectors)
        assert len(results) == len(vectors)
        assert all(isinstance(r, ModelResult) for r in results)

    def test_predict_scores_in_range(self, trained_ae):
        """All scores are in 0-1 range."""
        detector, vectors = trained_ae
        results = detector.predict(vectors)
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_predict_model_name(self, trained_ae):
        """All results have model_name='autoencoder'."""
        detector, vectors = trained_ae
        results = detector.predict(vectors)
        for r in results:
            assert r.model_name == "autoencoder"

    def test_predict_not_fitted(self):
        """Predicting without fitting returns empty list."""
        detector = AutoencoderDetector(input_dim=17)
        results = detector.predict([])
        assert results == []

    def test_predict_details_populated(self, trained_ae):
        """Results have populated details dict."""
        detector, vectors = trained_ae
        results = detector.predict(vectors)
        for r in results:
            assert "reconstruction_error" in r.details

    def test_predict_anomaly_detection(self):
        """AE detects anomalies in synthetic data."""
        conn = generate_zeek_conn_logs(n_events=300, anomaly_ratio=0.1, seed=42)
        dns = generate_zeek_dns_logs(n_events=50, seed=42)
        vectors = extract_event_features(conn, dns)
        detector = AutoencoderDetector(
            input_dim=17,
            hidden_dims=[32, 16],
            epochs=15,
            batch_size=16,
        )
        detector.fit(vectors)
        results = detector.predict(vectors)
        n_anomalies = sum(1 for r in results if r.is_anomaly)
        assert n_anomalies > 0


class TestAutoencoderReconstructionErrors:
    """Tests for reconstruction error computation."""

    def test_get_errors_basic(self, trained_ae):
        """get_reconstruction_errors returns list of floats."""
        detector, vectors = trained_ae
        errors = detector.get_reconstruction_errors(vectors)
        assert len(errors) == len(vectors)
        assert all(isinstance(e, float) for e in errors)

    def test_get_errors_non_negative(self, trained_ae):
        """Reconstruction errors are non-negative."""
        detector, vectors = trained_ae
        errors = detector.get_reconstruction_errors(vectors)
        for e in errors:
            assert e >= 0.0

    def test_get_errors_not_fitted(self):
        """get_reconstruction_errors on unfitted model returns empty list."""
        detector = AutoencoderDetector(input_dim=17)
        errors = detector.get_reconstruction_errors([])
        assert errors == []


class TestAutoencoderPersistence:
    """Tests for state dict save/load."""

    def test_state_dict_roundtrip(self, trained_ae):
        """get_state_dict and load_state_dict roundtrip."""
        detector, _ = trained_ae
        state = detector.get_state_dict()
        assert "state_dict" in state
        assert "input_dim" in state
        assert "threshold" in state

        # Create new detector and load
        new_detector = AutoencoderDetector(input_dim=17)
        new_detector.load_state_dict(state)
        assert new_detector.model is not None
        assert new_detector.threshold == detector.threshold
        assert new_detector.input_dim == detector.input_dim

    def test_state_dict_empty(self):
        """get_state_dict on unfitted model returns empty dict."""
        detector = AutoencoderDetector(input_dim=17)
        state = detector.get_state_dict()
        assert state == {}
