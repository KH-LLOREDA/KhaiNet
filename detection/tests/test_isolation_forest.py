"""Tests for Isolation Forest detector."""

from __future__ import annotations

import pytest

from src.feature_engineering import normalize_features
from src.isolation_forest import IsolationForestDetector
from src.models import FeatureVector, ModelResult
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs
from src.feature_engineering import extract_event_features


@pytest.fixture
def trained_if(sample_feature_vectors):
    """A trained Isolation Forest detector."""
    vectors, scaler = normalize_features(sample_feature_vectors)
    detector = IsolationForestDetector(n_estimators=50, random_state=42, threshold=0.6)
    detector.fit(vectors, scaler)
    return detector, vectors


class TestIsolationForestFit:
    """Tests for fitting the Isolation Forest."""

    def test_fit_basic(self, sample_feature_vectors):
        """Fit produces a non-None model."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        detector = IsolationForestDetector(n_estimators=20, random_state=42)
        detector.fit(vectors, scaler)
        assert detector.model is not None

    def test_fit_auto_normalizes(self, sample_feature_vectors):
        """Fit normalizes features if not already normalized."""
        detector = IsolationForestDetector(n_estimators=20, random_state=42)
        detector.fit(sample_feature_vectors)
        assert detector.model is not None
        assert detector.scaler is not None

    def test_fit_empty_features(self):
        """Fitting with empty features does not crash."""
        detector = IsolationForestDetector(n_estimators=10, random_state=42)
        detector.fit([])
        assert detector.model is None

    def test_fit_stores_feature_names(self, sample_feature_vectors):
        """Fit stores feature names."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        detector = IsolationForestDetector(n_estimators=20, random_state=42)
        detector.fit(vectors, scaler)
        assert len(detector.feature_names) > 0

    def test_fit_with_synthetic_data(self):
        """Fit with larger synthetic dataset."""
        conn = generate_zeek_conn_logs(n_events=200, seed=42)
        dns = generate_zeek_dns_logs(n_events=50, seed=42)
        vectors = extract_event_features(conn, dns)
        detector = IsolationForestDetector(n_estimators=50, random_state=42)
        detector.fit(vectors)
        assert detector.model is not None


class TestIsolationForestPredict:
    """Tests for predicting with the Isolation Forest."""

    def test_predict_basic(self, trained_if):
        """Predict produces ModelResult list."""
        detector, vectors = trained_if
        results = detector.predict(vectors)
        assert len(results) == len(vectors)
        assert all(isinstance(r, ModelResult) for r in results)

    def test_predict_scores_in_range(self, trained_if):
        """All scores are in 0-1 range."""
        detector, vectors = trained_if
        results = detector.predict(vectors)
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_predict_model_name(self, trained_if):
        """All results have model_name='isolation_forest'."""
        detector, vectors = trained_if
        results = detector.predict(vectors)
        for r in results:
            assert r.model_name == "isolation_forest"

    def test_predict_threshold_set(self, trained_if):
        """Results have the correct threshold."""
        detector, vectors = trained_if
        results = detector.predict(vectors)
        for r in results:
            assert r.threshold == detector.threshold

    def test_predict_not_fitted(self):
        """Predicting without fitting returns empty list."""
        detector = IsolationForestDetector()
        results = detector.predict([])
        assert results == []

    def test_predict_anomaly_detection(self):
        """IF detects anomalies in synthetic data with injected anomalies."""
        conn = generate_zeek_conn_logs(n_events=500, anomaly_ratio=0.1, seed=42)
        dns = generate_zeek_dns_logs(n_events=100, seed=42)
        vectors = extract_event_features(conn, dns)
        detector = IsolationForestDetector(
            n_estimators=50, random_state=42, threshold=0.5
        )
        detector.fit(vectors)
        results = detector.predict(vectors)
        # At least some should be flagged as anomalies
        n_anomalies = sum(1 for r in results if r.is_anomaly)
        assert n_anomalies > 0

    def test_predict_details_populated(self, trained_if):
        """Results have populated details dict."""
        detector, vectors = trained_if
        results = detector.predict(vectors)
        for r in results:
            assert "raw_score" in r.details
            assert "dst_ip" in r.details
            assert "dst_port" in r.details


class TestIsolationForestFeatureImportance:
    """Tests for feature importance."""

    def test_feature_importance_basic(self, trained_if):
        """get_feature_importance returns a dict."""
        detector, _ = trained_if
        importance = detector.get_feature_importance()
        assert isinstance(importance, dict)
        assert len(importance) > 0

    def test_feature_importance_values(self, trained_if):
        """Feature importance values are non-negative floats."""
        detector, _ = trained_if
        importance = detector.get_feature_importance()
        for name, value in importance.items():
            assert isinstance(value, float)
            assert value >= 0.0

    def test_feature_importance_not_fitted(self):
        """get_feature_importance on unfitted model returns empty dict."""
        detector = IsolationForestDetector()
        assert detector.get_feature_importance() == {}


class TestIsolationForestScoreNormalization:
    """Tests for score normalization."""

    def test_normalize_score_range(self, trained_if):
        """Normalized scores are in 0-1 range."""
        detector, _ = trained_if
        # Test with extreme values
        score_min = detector._normalize_score(detector._raw_max)
        score_max = detector._normalize_score(detector._raw_min)
        assert 0.0 <= score_min <= 1.0
        assert 0.0 <= score_max <= 1.0
        # More negative raw → higher normalized score
        assert score_max >= score_min

    def test_normalize_score_equal_range(self):
        """When raw_min == raw_max, score is 0.5."""
        detector = IsolationForestDetector()
        detector._raw_min = 1.0
        detector._raw_max = 1.0
        score = detector._normalize_score(1.0)
        assert score == 0.5
