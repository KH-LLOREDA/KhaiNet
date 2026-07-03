"""Tests for the drift checker."""

from __future__ import annotations

import numpy as np
import pytest

from src.drift_checker import DriftChecker, _calculate_psi, _severity


class TestPSI:
    def test_identical_distributions(self):
        """PSI of identical distributions should be ~0."""
        ref = np.array([0.1, 0.2, 0.3, 0.4, 0.5] * 20)
        psi = _calculate_psi(ref, ref)
        assert psi < 0.01

    def test_different_distributions(self):
        """PSI of very different distributions should be high."""
        ref = np.array([0.1, 0.15, 0.2, 0.25, 0.3] * 20)
        current = np.array([0.7, 0.75, 0.8, 0.85, 0.9] * 20)
        psi = _calculate_psi(ref, current)
        assert psi > 0.25  # Significant drift


class TestSeverity:
    def test_no_drift(self):
        assert _severity(0.1, 0.25) == "none"

    def test_low_drift(self):
        assert _severity(0.3, 0.25) == "low"  # 0.3/0.25 = 1.2

    def test_medium_drift(self):
        assert _severity(0.4, 0.25) == "medium"  # 0.4/0.25 = 1.6

    def test_high_drift(self):
        assert _severity(0.6, 0.25) == "high"  # 0.6/0.25 = 2.4


class TestDriftChecker:
    def test_no_drift(self):
        """Same distributions → no drift detected."""
        np.random.seed(42)
        ref = np.random.beta(2, 8, 500)
        current = np.random.beta(2, 8, 500)
        checker = DriftChecker({"model1": ref})
        results = checker.check_drift({"model1": current})
        assert "model1" in results
        # At least one metric should show no drift
        psi_result = next(r for r in results["model1"] if r.metric_name == "psi")
        # With same distribution, PSI should be low (may not be exactly 0 due to sampling)
        assert psi_result.value < 0.5  # Allow some sampling noise

    def test_drift_detected(self):
        """Different distributions → drift detected."""
        np.random.seed(42)
        ref = np.random.beta(2, 8, 500)  # Low scores
        current = np.random.beta(8, 2, 500)  # High scores
        checker = DriftChecker({"model1": ref})
        results = checker.check_drift({"model1": current})
        psi_result = next(r for r in results["model1"] if r.metric_name == "psi")
        assert psi_result.is_drifted is True
        assert psi_result.severity in ("low", "medium", "high")

    def test_multiple_models(self):
        np.random.seed(42)
        ref1 = np.random.beta(2, 8, 200)
        ref2 = np.random.beta(5, 5, 200)
        current1 = np.random.beta(2, 8, 200)  # No drift
        current2 = np.random.beta(8, 2, 200)  # Drift
        checker = DriftChecker({"model1": ref1, "model2": ref2})
        results = checker.check_drift({"model1": current1, "model2": current2})
        assert "model1" in results
        assert "model2" in results
        assert len(results["model1"]) == 3  # PSI, KS, Wasserstein
        assert len(results["model2"]) == 3

    def test_missing_reference_model(self):
        checker = DriftChecker({"model1": [0.1, 0.2, 0.3]})
        results = checker.check_drift({"unknown_model": [0.5, 0.6]})
        assert "unknown_model" not in results

    def test_three_metrics_present(self):
        ref = np.random.default_rng(42).beta(2, 8, 200)
        current = np.random.default_rng(99).beta(2, 8, 200)
        checker = DriftChecker({"model1": ref})
        results = checker.check_drift({"model1": current})
        metric_names = {r.metric_name for r in results["model1"]}
        assert metric_names == {"psi", "ks", "wasserstein"}


class TestRecommendRetuning:
    def test_no_retuning_needed(self):
        from src.models import DriftResult

        results = {
            "model1": [
                DriftResult(
                    metric_name="psi",
                    value=0.1,
                    threshold=0.25,
                    is_drifted=False,
                    severity="none",
                ),
                DriftResult(
                    metric_name="ks",
                    value=0.5,
                    threshold=0.05,
                    is_drifted=False,
                    severity="none",
                ),
            ]
        }
        checker = DriftChecker({"model1": [0.1, 0.2]})
        rec = checker.recommend_retuning(results)
        assert rec["needs_retuning"] == []

    def test_retuning_recommended(self):
        from src.models import DriftResult

        results = {
            "model1": [
                DriftResult(
                    metric_name="psi",
                    value=0.5,
                    threshold=0.25,
                    is_drifted=True,
                    severity="high",
                ),
                DriftResult(
                    metric_name="ks",
                    value=0.01,
                    threshold=0.05,
                    is_drifted=True,
                    severity="high",
                ),
            ],
            "model2": [
                DriftResult(
                    metric_name="psi",
                    value=0.1,
                    threshold=0.25,
                    is_drifted=False,
                    severity="none",
                ),
            ],
        }
        checker = DriftChecker({"model1": [0.1, 0.2], "model2": [0.3, 0.4]})
        rec = checker.recommend_retuning(results)
        assert "model1" in rec["needs_retuning"]
        assert "model2" not in rec["needs_retuning"]
        assert rec["summary"]["model1"]["max_severity"] == "high"
