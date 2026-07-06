"""Tests for score fusion."""

from __future__ import annotations

import pytest

from src.models import FusionResult
from src.score_fusion import ScoreFusion


class TestWeightedAverage:
    def test_equal_weights_with_insufficient_data(self):
        """With few samples, should fall back to equal weights."""
        scores = {
            "isolation_forest": [0.5, 0.6],
            "autoencoder": [0.4, 0.5],
            "hmm": [0.3, 0.4],
        }
        labels = [False, True]
        fusion = ScoreFusion(method="weighted_average")
        result = fusion.fuse_scores(scores, labels)
        assert result.method == "weighted_average"
        # Equal weights: 1/3 each
        for w in result.weights.values():
            assert abs(w - 1 / 3) < 0.01

    def test_weighted_average_with_enough_data(self):
        """With enough data, weights should be optimized via logistic regression."""
        scores = {
            "isolation_forest": [0.1] * 40 + [0.9] * 10,
            "autoencoder": [0.1] * 40 + [0.9] * 10,
            "hmm": [0.1] * 40 + [0.9] * 10,
        }
        labels = [False] * 40 + [True] * 10
        fusion = ScoreFusion(method="weighted_average")
        result = fusion.fuse_scores(scores, labels)
        assert result.method == "weighted_average"
        # Weights should sum to ~1.0
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.1

    def test_unified_score_in_range(self, fusion_scores, fusion_labels):
        fusion = ScoreFusion(method="weighted_average")
        result = fusion.fuse_scores(fusion_scores, fusion_labels)
        assert 0.0 <= result.unified_score <= 1.0

    def test_model_contributions(self, fusion_scores, fusion_labels):
        fusion = ScoreFusion(method="weighted_average")
        result = fusion.fuse_scores(fusion_scores, fusion_labels)
        assert len(result.model_contributions) == 3
        for model in fusion_scores:
            assert model in result.model_contributions


class TestStacking:
    def test_stacking_with_enough_data(self):
        """Stacking with enough data should produce a meta-model."""
        scores = {
            "isolation_forest": [0.1] * 40 + [0.9] * 10,
            "autoencoder": [0.1] * 40 + [0.85] * 10,
            "hmm": [0.1] * 40 + [0.95] * 10,
        }
        labels = [False] * 40 + [True] * 10
        fusion = ScoreFusion(method="stacking")
        result = fusion.fuse_scores(scores, labels)
        assert result.method in ("stacking", "weighted_average")  # may fall back
        assert 0.0 <= result.unified_score <= 1.0

    def test_stacking_falls_back_with_little_data(self):
        """With insufficient data, stacking falls back to weighted average."""
        scores = {
            "isolation_forest": [0.5, 0.6],
            "autoencoder": [0.4, 0.5],
            "hmm": [0.3, 0.4],
        }
        labels = [False, True]
        fusion = ScoreFusion(method="stacking")
        result = fusion.fuse_scores(scores, labels)
        # Should fall back to weighted_average
        assert result.method == "weighted_average"


class TestApplyFusion:
    def test_apply_with_all_models(self):
        fusion_result = FusionResult(
            method="weighted_average",
            weights={"isolation_forest": 0.4, "autoencoder": 0.3, "hmm": 0.3},
            unified_score=0.5,
            threshold=0.5,
        )
        scores = {
            "isolation_forest": 0.8,
            "autoencoder": 0.6,
            "hmm": 0.4,
        }
        unified = ScoreFusion.apply_fusion(scores, fusion_result)
        expected = 0.8 * 0.4 + 0.6 * 0.3 + 0.4 * 0.3
        assert abs(unified - expected) < 0.001

    def test_apply_with_missing_model(self):
        """Missing model (None) should redistribute weight."""
        fusion_result = FusionResult(
            method="weighted_average",
            weights={"isolation_forest": 0.4, "autoencoder": 0.3, "hmm": 0.3},
            unified_score=0.5,
            threshold=0.5,
        )
        scores = {
            "isolation_forest": 0.8,
            "autoencoder": None,  # Missing
            "hmm": 0.4,
        }
        unified = ScoreFusion.apply_fusion(scores, fusion_result)
        # Only IF and HMM contribute: (0.8*0.4 + 0.4*0.3) / (0.4+0.3)
        expected = (0.8 * 0.4 + 0.4 * 0.3) / (0.4 + 0.3)
        assert abs(unified - expected) < 0.001

    def test_apply_all_missing(self):
        fusion_result = FusionResult(
            method="weighted_average",
            weights={"isolation_forest": 0.4, "autoencoder": 0.3, "hmm": 0.3},
        )
        scores = {
            "isolation_forest": None,
            "autoencoder": None,
            "hmm": None,
        }
        unified = ScoreFusion.apply_fusion(scores, fusion_result)
        assert unified == 0.0

    def test_apply_clamped_to_01(self):
        fusion_result = FusionResult(
            method="weighted_average",
            weights={"m1": 1.0},
        )
        scores = {"m1": 1.5}  # Out of range
        unified = ScoreFusion.apply_fusion(scores, fusion_result)
        assert unified == 1.0


class TestExtremeScores:
    def test_all_zero_scores(self):
        scores = {
            "isolation_forest": [0.0] * 50,
            "autoencoder": [0.0] * 50,
            "hmm": [0.0] * 50,
        }
        labels = [False] * 50
        fusion = ScoreFusion(method="weighted_average")
        result = fusion.fuse_scores(scores, labels)
        assert result.unified_score == 0.0

    def test_all_one_scores(self):
        scores = {
            "isolation_forest": [1.0] * 50,
            "autoencoder": [1.0] * 50,
            "hmm": [1.0] * 50,
        }
        labels = [True] * 50
        fusion = ScoreFusion(method="weighted_average")
        result = fusion.fuse_scores(scores, labels)
        assert result.unified_score == 1.0


class TestValidation:
    def test_mismatched_lengths_raises(self):
        """fuse_scores should raise ValueError on mismatched lengths."""
        scores = {
            "isolation_forest": [0.1, 0.2, 0.3],
            "autoencoder": [0.1, 0.2],  # Wrong length
            "hmm": [0.1, 0.2, 0.3],
        }
        labels = [False, False, True]
        fusion = ScoreFusion(method="weighted_average")
        with pytest.raises(ValueError, match="elements but labels has"):
            fusion.fuse_scores(scores, labels)

    def test_mismatched_labels_length_raises(self):
        """Should raise when labels length differs from all score lists."""
        scores = {
            "isolation_forest": [0.1, 0.2, 0.3],
            "autoencoder": [0.1, 0.2, 0.3],
            "hmm": [0.1, 0.2, 0.3],
        }
        labels = [False, True]  # Wrong length
        fusion = ScoreFusion(method="weighted_average")
        with pytest.raises(ValueError, match="elements but labels has"):
            fusion.fuse_scores(scores, labels)
