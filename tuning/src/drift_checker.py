"""Drift checker: detect distribution drift in model scores.

Compares current model scores against a reference distribution (from the
training/tuning period) using three metrics:

1. **PSI (Population Stability Index)**: >0.25 indicates significant drift.
2. **KS-test (Kolmogorov-Smirnov)**: p-value < 0.05 indicates drift.
3. **Wasserstein distance**: measures the "work" needed to transform one
   distribution into another.

If drift is detected, the checker recommends re-tuning the affected model(s).
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
from scipy.stats import ks_2samp, wasserstein_distance

from src.models import DriftResult

log = structlog.get_logger()

# Default thresholds
DEFAULT_PSI_THRESHOLD = 0.25
DEFAULT_KS_PVALUE_THRESHOLD = 0.05
DEFAULT_WASSERSTEIN_THRESHOLD = 0.1


def _calculate_psi(
    reference: np.ndarray, current: np.ndarray, n_bins: int = 10
) -> float:
    """Calculate Population Stability Index (PSI).

    PSI = Σ (p_current - p_reference) * ln(p_current / p_reference)

    Args:
        reference: Reference distribution scores.
        current: Current distribution scores.
        n_bins: Number of bins for histogram comparison.

    Returns:
        PSI value (0 = no drift, >0.25 = significant drift).
    """
    # Use reference bins for both distributions
    bins = np.linspace(0, 1, n_bins + 1)
    ref_hist, _ = np.histogram(reference, bins=bins)
    cur_hist, _ = np.histogram(current, bins=bins)

    # Normalize to proportions, avoid division by zero
    ref_prop = ref_hist / len(reference) if len(reference) > 0 else ref_hist
    cur_prop = cur_hist / len(current) if len(current) > 0 else cur_hist

    # Add small epsilon to avoid log(0)
    eps = 1e-6
    ref_prop = np.clip(ref_prop, eps, None)
    cur_prop = np.clip(cur_prop, eps, None)

    psi = np.sum((cur_prop - ref_prop) * np.log(cur_prop / ref_prop))
    return float(psi)


def _severity(value: float, threshold: float) -> str:
    """Determine drift severity based on value vs threshold.

    Args:
        value: Metric value.
        threshold: Drift threshold.

    Returns:
        Severity string: none, low, medium, high.
    """
    if value < threshold:
        return "none"
    ratio = value / threshold if threshold > 0 else 0
    if ratio < 1.5:
        return "low"
    if ratio < 2.0:
        return "medium"
    return "high"


class DriftChecker:
    """Check for distribution drift in model scores.

    Args:
        reference_scores: Reference score distributions per model
            (dict mapping model name → list of scores from tuning period).
        psi_threshold: PSI threshold for drift detection.
        ks_pvalue_threshold: KS-test p-value threshold (below = drift).
        wasserstein_threshold: Wasserstein distance threshold.
    """

    def __init__(
        self,
        reference_scores: dict[str, list[float]],
        psi_threshold: float = DEFAULT_PSI_THRESHOLD,
        ks_pvalue_threshold: float = DEFAULT_KS_PVALUE_THRESHOLD,
        wasserstein_threshold: float = DEFAULT_WASSERSTEIN_THRESHOLD,
    ) -> None:
        self.reference_scores = {
            k: np.asarray(v, dtype=float) for k, v in reference_scores.items()
        }
        self.psi_threshold = psi_threshold
        self.ks_pvalue_threshold = ks_pvalue_threshold
        self.wasserstein_threshold = wasserstein_threshold

    def check_drift(
        self,
        current_scores: dict[str, list[float]],
        threshold: float = 0.2,
    ) -> dict[str, list[DriftResult]]:
        """Check for drift in current scores vs reference.

        Args:
            current_scores: Current score distributions per model.
            threshold: General drift threshold (used as PSI fallback).

        Returns:
            Dict mapping model name → list of DriftResult (one per metric).
        """
        results: dict[str, list[DriftResult]] = {}

        for model_name, current in current_scores.items():
            current_arr = np.asarray(current, dtype=float)
            model_results: list[DriftResult] = []

            if model_name not in self.reference_scores:
                log.warning(
                    "no_reference_for_model",
                    model=model_name,
                )
                continue

            reference = self.reference_scores[model_name]

            # PSI
            psi_value = _calculate_psi(reference, current_arr)
            psi_drifted = psi_value > self.psi_threshold
            model_results.append(
                DriftResult(
                    metric_name="psi",
                    value=psi_value,
                    threshold=self.psi_threshold,
                    is_drifted=psi_drifted,
                    severity=_severity(psi_value, self.psi_threshold),
                )
            )

            # KS-test
            _ks_stat, ks_pvalue = ks_2samp(reference, current_arr)
            ks_drifted = ks_pvalue < self.ks_pvalue_threshold
            model_results.append(
                DriftResult(
                    metric_name="ks",
                    value=float(ks_pvalue),
                    threshold=self.ks_pvalue_threshold,
                    is_drifted=ks_drifted,
                    severity="high" if ks_drifted else "none",
                )
            )

            # Wasserstein distance
            w_dist = wasserstein_distance(reference, current_arr)
            w_drifted = w_dist > self.wasserstein_threshold
            model_results.append(
                DriftResult(
                    metric_name="wasserstein",
                    value=float(w_dist),
                    threshold=self.wasserstein_threshold,
                    is_drifted=w_drifted,
                    severity=_severity(w_dist, self.wasserstein_threshold),
                )
            )

            results[model_name] = model_results

            any_drift = any(r.is_drifted for r in model_results)
            log.info(
                "drift_check_complete",
                model=model_name,
                psi=psi_value,
                ks_pvalue=ks_pvalue,
                wasserstein=w_dist,
                drift_detected=any_drift,
            )

        return results

    def recommend_retuning(
        self, drift_results: dict[str, list[DriftResult]]
    ) -> dict[str, Any]:
        """Generate re-tuning recommendations based on drift results.

        Args:
            drift_results: Output of ``check_drift``.

        Returns:
            Dict with models needing re-tuning and severity summary.
        """
        recommendations: dict[str, Any] = {
            "needs_retuning": [],
            "summary": {},
        }

        for model_name, results in drift_results.items():
            drifted_metrics = [r for r in results if r.is_drifted]
            if drifted_metrics:
                max_severity = max(
                    (r.severity for r in drifted_metrics),
                    key=lambda s: {"none": 0, "low": 1, "medium": 2, "high": 3}.get(
                        s, 0
                    ),
                )
                recommendations["needs_retuning"].append(model_name)
                recommendations["summary"][model_name] = {
                    "drifted_metrics": [r.metric_name for r in drifted_metrics],
                    "max_severity": max_severity,
                }

        if recommendations["needs_retuning"]:
            log.warning(
                "retuning_recommended",
                models=recommendations["needs_retuning"],
            )

        return recommendations
