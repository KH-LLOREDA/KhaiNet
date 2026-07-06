"""Score fusion: ensemble the 3 model scores into a unified anomaly score.

Two fusion methods:

1. **Weighted Average**: weights optimized via logistic regression on the
   labels. Falls back to equal weights (1/3 each) if insufficient data.
   ``unified = (w1*s1 + w2*s2 + w3*s3) / (w1+w2+w3)``

2. **Stacking**: a meta-model (LogisticRegression) trained on the 3 scores
   via cross-validation to avoid overfitting. The meta-model's predicted
   probability is the unified score.

Handles missing models (score=None) by redistributing weight to present models.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict

from src.models import FusionResult

log = structlog.get_logger()

DEFAULT_WEIGHTS: dict[str, float] = {
    "isolation_forest": 1 / 3,
    "autoencoder": 1 / 3,
    "hmm": 1 / 3,
}


class ScoreFusion:
    """Fuse scores from multiple models into a unified anomaly score.

    Args:
        method: Fusion method ("weighted_average" or "stacking").
        default_weights: Fallback weights when optimization isn't possible.
    """

    def __init__(
        self,
        method: str = "weighted_average",
        default_weights: dict[str, float] | None = None,
    ) -> None:
        self.method = method
        self.default_weights = default_weights or dict(DEFAULT_WEIGHTS)

    # ------------------------------------------------------------------
    # Weighted average
    # ------------------------------------------------------------------

    def _optimize_weights(
        self,
        scores: dict[str, list[float]],
        labels: list[bool],
    ) -> dict[str, float]:
        """Optimize fusion weights using logistic regression.

        Uses the logistic regression coefficients as relative weights.
        Falls back to default weights if optimization fails.

        Args:
            scores: Dict mapping model name → list of scores.
            labels: Ground-truth labels.

        Returns:
            Dict mapping model name → weight (normalized to sum=1).
        """
        model_names = list(scores.keys())
        n_samples = len(labels)

        # Need enough positive samples for meaningful optimization
        n_positive = sum(labels)
        if n_samples < 50 or n_positive < 5:
            log.info(
                "insufficient_data_for_weight_optimization",
                n_samples=n_samples,
                n_positive=n_positive,
                fallback="equal_weights",
            )
            return {m: 1.0 / len(model_names) for m in model_names}

        # Build feature matrix
        X = np.column_stack([scores[m] for m in model_names])
        y = np.asarray(labels, dtype=int)

        try:
            lr = LogisticRegression(max_iter=1000, random_state=42)
            lr.fit(X, y)
            coefs = np.abs(lr.coef_[0])
            # Normalize to sum=1
            total = coefs.sum()
            if total == 0:
                return {m: 1.0 / len(model_names) for m in model_names}
            weights = coefs / total
            return {m: float(w) for m, w in zip(model_names, weights)}
        except Exception as exc:
            log.warning("weight_optimization_failed", error=str(exc))
            return {m: 1.0 / len(model_names) for m in model_names}

    def _weighted_average(
        self,
        scores: dict[str, list[float]],
        labels: list[bool],
    ) -> FusionResult:
        """Fuse scores using weighted average."""
        weights = self._optimize_weights(scores, labels)
        model_names = list(scores.keys())
        n = len(labels)

        unified_scores: list[float] = []
        contributions: dict[str, Any] = {m: 0.0 for m in model_names}

        for i in range(n):
            total_weight = 0.0
            weighted_sum = 0.0
            for m in model_names:
                s = scores[m][i]
                w = weights[m]
                weighted_sum += s * w
                total_weight += w
                contributions[m] = contributions[m] + s * w
            unified = weighted_sum / total_weight if total_weight > 0 else 0.0
            unified_scores.append(float(np.clip(unified, 0.0, 1.0)))

        # Average contributions
        for m in model_names:
            contributions[m] = float(contributions[m] / n) if n > 0 else 0.0

        # Threshold: use 0.5 as default (can be tuned separately)
        threshold = 0.5
        avg_unified = float(np.mean(unified_scores)) if unified_scores else 0.0

        return FusionResult(
            method="weighted_average",
            weights=weights,
            unified_score=avg_unified,
            threshold=threshold,
            model_contributions=contributions,
        )

    # ------------------------------------------------------------------
    # Stacking
    # ------------------------------------------------------------------

    def _stacking(
        self,
        scores: dict[str, list[float]],
        labels: list[bool],
    ) -> FusionResult:
        """Fuse scores using stacking with a logistic regression meta-model."""
        model_names = list(scores.keys())
        n = len(labels)
        n_positive = sum(labels)

        X = np.column_stack([scores[m] for m in model_names])
        y = np.asarray(labels, dtype=int)

        if n < 50 or n_positive < 5:
            log.info(
                "insufficient_data_for_stacking",
                n_samples=n,
                n_positive=n_positive,
                fallback="weighted_average",
            )
            return self._weighted_average(scores, labels)

        # Cross-validated predictions to avoid overfitting
        try:
            meta_model = LogisticRegression(max_iter=1000, random_state=42)
            cv_preds = cross_val_predict(
                meta_model, X, y, cv=min(5, n_positive), method="predict_proba"
            )
            unified_scores = cv_preds[:, 1]

            # Fit final model on all data
            meta_model.fit(X, y)
            coefs = meta_model.coef_[0]
            total = np.abs(coefs).sum()
            weights = (
                {m: float(np.abs(c) / total) for m, c in zip(model_names, coefs)}
                if total > 0
                else {m: 1.0 / len(model_names) for m in model_names}
            )

            contributions: dict[str, Any] = {m: 0.0 for m in model_names}
            for i in range(n):
                for m_idx, m in enumerate(model_names):
                    contributions[m] += float(X[i, m_idx] * weights[m])
            for m in model_names:
                contributions[m] = float(contributions[m] / n) if n > 0 else 0.0

            threshold = 0.5
            avg_unified = float(np.mean(unified_scores))

            return FusionResult(
                method="stacking",
                weights=weights,
                unified_score=avg_unified,
                threshold=threshold,
                model_contributions=contributions,
                meta_model_params={
                    "coef": [float(c) for c in meta_model.coef_[0]],
                    "intercept": float(meta_model.intercept_[0]),
                },
            )
        except Exception as exc:
            log.warning("stacking_failed", error=str(exc), fallback="weighted_average")
            return self._weighted_average(scores, labels)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuse_scores(
        self,
        scores: dict[str, list[float]],
        labels: list[bool],
        method: str | None = None,
    ) -> FusionResult:
        """Fuse scores from multiple models into a unified score.

        Args:
            scores: Dict mapping model name → list of scores (0-1).
            labels: Ground-truth labels (True=anomaly).
            method: Override fusion method.

        Returns:
            FusionResult with weights, unified score, and contributions.

        Raises:
            ValueError: If scores and labels have mismatched lengths.
        """
        # Validate that all score lists have the same length as labels
        n_labels = len(labels)
        for model_name, model_scores in scores.items():
            if len(model_scores) != n_labels:
                raise ValueError(
                    f"Score list for model '{model_name}' has {len(model_scores)} "
                    f"elements but labels has {n_labels}"
                )

        m = method or self.method
        if m == "stacking":
            result = self._stacking(scores, labels)
        else:
            result = self._weighted_average(scores, labels)

        log.info(
            "scores_fused",
            method=result.method,
            models=list(scores.keys()),
            weights=result.weights,
            unified_score=result.unified_score,
        )
        return result

    @staticmethod
    def apply_fusion(
        scores: dict[str, float | None],
        fusion_result: FusionResult,
    ) -> float:
        """Apply a trained fusion to a single event's scores.

        Handles missing models (score=None) by redistributing weight.

        Args:
            scores: Dict mapping model name → score (or None if missing).
            fusion_result: Trained fusion result with weights.

        Returns:
            Unified score in [0, 1].
        """
        weights = fusion_result.weights
        total_weight = 0.0
        weighted_sum = 0.0

        for model_name, score in scores.items():
            if score is None:
                continue
            w = weights.get(model_name, 0.0)
            weighted_sum += score * w
            total_weight += w

        if total_weight == 0:
            return 0.0

        unified = weighted_sum / total_weight
        return float(np.clip(unified, 0.0, 1.0))
