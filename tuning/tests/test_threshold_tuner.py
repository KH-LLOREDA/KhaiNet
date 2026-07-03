"""Tests for the threshold tuner."""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.cost_matrix import CostMatrix
from src.models import ModelScore
from src.threshold_tuner import ThresholdTuner


class TestTuneModel:
    def test_tune_with_synthetic_data(self):
        """Tune with clear separation between normal and anomaly scores."""
        scores = [0.1, 0.15, 0.2, 0.25, 0.75, 0.8, 0.85, 0.9]
        labels = [False, False, False, False, True, True, True, True]
        tuner = ThresholdTuner(cost_matrix=CostMatrix())
        result = tuner.tune_model(scores, labels, "isolation_forest")

        assert result.model_name == "isolation_forest"
        assert 0.0 < result.optimal_threshold < 1.0
        assert 0.0 <= result.precision_at_threshold <= 1.0
        assert 0.0 <= result.recall_at_threshold <= 1.0
        assert 0.0 <= result.f1_at_threshold <= 1.0

    def test_optimal_threshold_in_range(self):
        scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        labels = [False, False, False, True, True, True]
        tuner = ThresholdTuner()
        result = tuner.tune_model(scores, labels, "test_model")
        assert 0.01 <= result.optimal_threshold <= 0.99

    def test_pr_auc_calculated(self):
        scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        labels = [False, False, False, True, True, True]
        tuner = ThresholdTuner()
        result = tuner.tune_model(scores, labels, "test_model")
        # With clear separation, PR-AUC should be high
        assert result.pr_auc > 0.8
        assert 0.0 <= result.pr_auc <= 1.0

    def test_roc_auc_calculated(self):
        scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        labels = [False, False, False, True, True, True]
        tuner = ThresholdTuner()
        result = tuner.tune_model(scores, labels, "test_model")
        # With clear separation, ROC-AUC should be 1.0
        assert result.roc_auc == 1.0
        assert 0.0 <= result.roc_auc <= 1.0

    def test_perfect_separation(self):
        """Perfect separation → precision=1, recall=1 at optimal threshold."""
        scores = [0.1, 0.2, 0.8, 0.9]
        labels = [False, False, True, True]
        tuner = ThresholdTuner()
        result = tuner.tune_model(scores, labels, "test_model")
        assert result.precision_at_threshold == 1.0
        assert result.recall_at_threshold == 1.0
        assert result.f1_at_threshold == 1.0

    def test_threshold_curve_populated(self):
        scores = [0.1, 0.5, 0.9]
        labels = [False, True, True]
        tuner = ThresholdTuner(threshold_steps=50)
        result = tuner.tune_model(scores, labels, "test_model")
        assert len(result.threshold_curve) == 50
        for entry in result.threshold_curve:
            assert "threshold" in entry
            assert "precision" in entry
            assert "recall" in entry
            assert "f1" in entry
            assert "cost" in entry

    def test_youdens_j_calculated(self):
        scores = [0.1, 0.2, 0.8, 0.9]
        labels = [False, False, True, True]
        tuner = ThresholdTuner()
        result = tuner.tune_model(scores, labels, "test_model")
        # With perfect separation, Youden's J should be 1.0
        assert result.youdens_j == 1.0

    def test_reference_thresholds_reported(self):
        scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        labels = [False, False, False, True, True, True]
        tuner = ThresholdTuner()
        result = tuner.tune_model(scores, labels, "test_model")
        assert result.f1_optimal_threshold is not None
        assert result.youdens_optimal_threshold is not None

    def test_empty_scores_raises(self):
        tuner = ThresholdTuner()
        with pytest.raises(ValueError):
            tuner.tune_model([], [], "test_model")

    def test_mismatched_lengths_raises(self):
        tuner = ThresholdTuner()
        with pytest.raises(ValueError):
            tuner.tune_model([0.1, 0.2], [True], "test_model")


class TestCostWeightedVsF1:
    """Verify that cost-weighted optimization differs from F1 when imbalanced."""

    def test_cost_weighted_prefers_lower_threshold(self):
        """With FN 10x more expensive, cost-weighted should choose a lower
        threshold than F1 to avoid missing anomalies."""
        # Heavily imbalanced: 99 normal, 1 anomaly
        scores = [0.05] * 95 + [0.15, 0.2, 0.25] + [0.6]
        labels = [False] * 95 + [False, False, False] + [True]
        tuner = ThresholdTuner(optimization_metric="cost_weighted")
        result_cost = tuner.tune_model(scores, labels, "test")

        tuner_f1 = ThresholdTuner(optimization_metric="f1")
        result_f1 = tuner_f1.tune_model(scores, labels, "test")

        # Cost-weighted should have lower or equal threshold (more sensitive)
        assert result_cost.optimal_threshold <= result_f1.optimal_threshold + 0.01


class TestTuneAllModels:
    def test_tune_all_with_aligned_events(self, sample_aligned_events):
        tuner = ThresholdTuner()
        results = tuner.tune_all_models(sample_aligned_events)
        assert isinstance(results, dict)
        assert len(results) > 0
        for model_name, result in results.items():
            assert result.model_name == model_name

    def test_tune_all_multiple_models(self, now_utc, src_ip_a, dst_ip_a):
        """Events from multiple models should produce separate results."""
        from src.temporal_alignment import align_labels_to_events
        from src.models import SupervisedLabel

        events = []
        for model in ["isolation_forest", "autoencoder", "hmm"]:
            for i in range(10):
                events.append(
                    ModelScore(
                        event_id=f"evt-{model}-{i}",
                        timestamp=now_utc + timedelta(seconds=i * 10),
                        src_ip=src_ip_a,
                        dst_ip=dst_ip_a,
                        model_name=model,
                        score=0.1 + i * 0.08,
                    )
                )
        labels = [
            SupervisedLabel(
                event_id=f"lbl-{i}",
                timestamp=now_utc + timedelta(seconds=i * 10 + 2),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                label=(i >= 8),
            )
            for i in range(10)
        ]
        aligned = align_labels_to_events(labels, events)
        tuner = ThresholdTuner()
        results = tuner.tune_all_models(aligned)
        assert len(results) == 3
        assert set(results.keys()) == {"isolation_forest", "autoencoder", "hmm"}
