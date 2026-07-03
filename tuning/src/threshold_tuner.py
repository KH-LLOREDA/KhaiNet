"""Threshold tuner: optimize decision thresholds for each ML model.

For each model (Isolation Forest, Autoencoder, HMM), calculates:
- ROC curve and ROC-AUC
- PR curve and PR-AUC
- Youden's J statistic at each threshold
- F1-score at each threshold
- Cost-weighted score at each threshold

The **optimal threshold** maximizes the cost-weighted score (not F1),
because in cybersecurity the classes are heavily imbalanced (1:1000+)
and false negatives are 10× more costly than false positives.

Also reports the F1-optimal and Youden-optimal thresholds as reference.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from src.cost_matrix import CostMatrix
from src.models import AlignedEvent, TuningResult

log = structlog.get_logger()


class ThresholdTuner:
    """Threshold optimizer for anomaly detection models.

    Args:
        cost_matrix: Cost matrix for cost-weighted optimization.
        min_threshold: Minimum threshold to evaluate.
        max_threshold: Maximum threshold to evaluate.
        threshold_steps: Number of threshold steps.
        optimization_metric: Metric to optimize (cost_weighted, f1, youdens_j).
    """

    def __init__(
        self,
        cost_matrix: CostMatrix | None = None,
        min_threshold: float = 0.01,
        max_threshold: float = 0.99,
        threshold_steps: int = 100,
        optimization_metric: str = "cost_weighted",
    ) -> None:
        self.cost_matrix = cost_matrix or CostMatrix()
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.threshold_steps = threshold_steps
        self.optimization_metric = optimization_metric
        self._thresholds = np.linspace(min_threshold, max_threshold, threshold_steps)

    # ------------------------------------------------------------------
    # Core tuning
    # ------------------------------------------------------------------

    def tune_model(
        self,
        scores: list[float] | np.ndarray,
        labels: list[bool] | np.ndarray,
        model_name: str,
    ) -> TuningResult:
        """Tune the threshold for a single model.

        Args:
            scores: Model scores (0-1).
            labels: Ground-truth labels (True=anomaly).
            model_name: Name of the model.

        Returns:
            TuningResult with optimal threshold and all metrics.
        """
        scores_arr = np.asarray(scores, dtype=float)
        labels_arr = np.asarray(labels, dtype=bool).astype(int)

        if len(scores_arr) == 0 or len(labels_arr) == 0:
            raise ValueError(f"Empty scores or labels for model {model_name}")

        if len(scores_arr) != len(labels_arr):
            raise ValueError(
                f"Scores ({len(scores_arr)}) and labels ({len(labels_arr)}) "
                f"length mismatch for model {model_name}"
            )

        # ROC curve and AUC (handle single-class case)
        n_positive = int(np.sum(labels_arr))
        n_negative = int(np.sum(~labels_arr.astype(bool)))
        if n_positive == 0 or n_negative == 0:
            # Only one class present → AUC is undefined, default to 0.5
            roc_auc = 0.5
            pr_auc = 0.0 if n_positive == 0 else 1.0
        else:
            _fpr, _tpr, _roc_thresholds = roc_curve(labels_arr, scores_arr)
            roc_auc = float(roc_auc_score(labels_arr, scores_arr))

            # PR curve and AUC
            _precision_curve, _recall_curve, _pr_thresholds = precision_recall_curve(
                labels_arr, scores_arr
            )
            pr_auc = float(average_precision_score(labels_arr, scores_arr))

        # Build threshold curve: evaluate all metrics at each threshold
        threshold_curve: list[dict[str, Any]] = []
        best_cost = float("-inf")
        best_cost_threshold = 0.5
        best_f1 = 0.0
        best_f1_threshold = 0.5
        best_youdens_j = -1.0
        best_youdens_threshold = 0.5

        for t in self._thresholds:
            y_pred = (scores_arr >= t).astype(int)

            # Confusion matrix components
            tp = int(np.sum((labels_arr == 1) & (y_pred == 1)))
            fp = int(np.sum((labels_arr == 0) & (y_pred == 1)))
            fn = int(np.sum((labels_arr == 1) & (y_pred == 0)))
            tn = int(np.sum((labels_arr == 0) & (y_pred == 0)))

            # Metrics
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            cost = self.cost_matrix.calculate_cost(tp, fp, fn, tn)

            # Youden's J: TPR - FPR
            tpr_val = rec  # = tp / (tp + fn)
            fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            youdens_j = tpr_val - fpr_val

            threshold_curve.append(
                {
                    "threshold": float(t),
                    "precision": prec,
                    "recall": rec,
                    "f1": f1,
                    "cost": cost,
                    "youdens_j": youdens_j,
                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                    "tn": tn,
                }
            )

            # Track bests
            if cost > best_cost:
                best_cost = cost
                best_cost_threshold = float(t)
            if f1 > best_f1:
                best_f1 = f1
                best_f1_threshold = float(t)
            if youdens_j > best_youdens_j:
                best_youdens_j = youdens_j
                best_youdens_threshold = float(t)

        # Select optimal threshold based on optimization_metric
        if self.optimization_metric == "f1":
            optimal_threshold = best_f1_threshold
        elif self.optimization_metric == "youdens_j":
            optimal_threshold = best_youdens_threshold
        else:  # cost_weighted (default)
            optimal_threshold = best_cost_threshold

        # Metrics at optimal threshold
        y_pred_opt = (scores_arr >= optimal_threshold).astype(int)
        prec_at = float(precision_score(labels_arr, y_pred_opt, zero_division=0))
        rec_at = float(recall_score(labels_arr, y_pred_opt, zero_division=0))
        f1_at = float(f1_score(labels_arr, y_pred_opt, zero_division=0))

        result = TuningResult(
            model_name=model_name,
            optimal_threshold=optimal_threshold,
            precision_at_threshold=prec_at,
            recall_at_threshold=rec_at,
            f1_at_threshold=f1_at,
            pr_auc=pr_auc,
            roc_auc=roc_auc,
            youdens_j=best_youdens_j,
            cost_at_threshold=best_cost,
            threshold_curve=threshold_curve,
            f1_optimal_threshold=best_f1_threshold,
            youdens_optimal_threshold=best_youdens_threshold,
        )

        log.info(
            "model_tuned",
            model=model_name,
            optimal_threshold=optimal_threshold,
            metric=self.optimization_metric,
            precision=prec_at,
            recall=rec_at,
            f1=f1_at,
            pr_auc=pr_auc,
            roc_auc=roc_auc,
            cost=best_cost,
        )
        return result

    # ------------------------------------------------------------------
    # Batch tuning
    # ------------------------------------------------------------------

    def tune_all_models(
        self,
        aligned_events: list[AlignedEvent],
        cost_matrix: CostMatrix | None = None,
    ) -> dict[str, TuningResult]:
        """Tune thresholds for all models present in the aligned events.

        Groups events by model_name and tunes each independently.

        Args:
            aligned_events: Aligned events with scores and labels.
            cost_matrix: Optional override cost matrix.

        Returns:
            Dict mapping model_name → TuningResult.
        """
        cm = cost_matrix or self.cost_matrix

        # Group by model name
        model_groups: dict[str, tuple[list[float], list[bool]]] = {}
        for ae in aligned_events:
            name = ae.model_name
            if name not in model_groups:
                model_groups[name] = ([], [])
            model_groups[name][0].append(ae.score)
            model_groups[name][1].append(ae.label)

        results: dict[str, TuningResult] = {}
        for model_name, (scores, labels) in model_groups.items():
            tuner = ThresholdTuner(
                cost_matrix=cm,
                min_threshold=self.min_threshold,
                max_threshold=self.max_threshold,
                threshold_steps=self.threshold_steps,
                optimization_metric=self.optimization_metric,
            )
            results[model_name] = tuner.tune_model(scores, labels, model_name)

        log.info(
            "all_models_tuned",
            models=list(results.keys()),
            n_events=len(aligned_events),
        )
        return results

    # ------------------------------------------------------------------
    # Confidence-weighted tuning (for weak supervision labels)
    # ------------------------------------------------------------------

    def tune_model_weighted(
        self,
        scores: list[float] | np.ndarray,
        labels: list[bool] | np.ndarray,
        confidences: list[float] | np.ndarray | None = None,
        model_name: str = "unknown",
    ) -> TuningResult:
        """Tune threshold with confidence-weighted labels.

        When labels come from weak supervision (multiple sources with varying
        confidence), each label's contribution to the cost function is weighted
        by its confidence. A label with confidence=0.5 contributes half as
        much to the cost as a label with confidence=1.0.

        This is the key adaptation for the auto-labeling pipeline: instead of
        treating all labels as equally reliable (binary), we weight them by
        how confident the weak supervisor is about each one.

        Args:
            scores: Model scores (0-1).
            labels: Ground-truth labels (True=anomaly).
            confidences: Confidence weights for each label (0-1). If None,
                defaults to 1.0 for all (equivalent to tune_model).
            model_name: Name of the model.

        Returns:
            TuningResult with optimal threshold and all metrics.
        """
        scores_arr = np.asarray(scores, dtype=float)
        labels_arr = np.asarray(labels, dtype=bool).astype(int)

        if confidences is None:
            confidences_arr = np.ones(len(labels_arr), dtype=float)
        else:
            confidences_arr = np.asarray(confidences, dtype=float)

        if len(scores_arr) == 0 or len(labels_arr) == 0:
            raise ValueError(f"Empty scores or labels for model {model_name}")

        if len(scores_arr) != len(labels_arr):
            raise ValueError(
                f"Scores ({len(scores_arr)}) and labels ({len(labels_arr)}) "
                f"length mismatch for model {model_name}"
            )

        if len(confidences_arr) != len(labels_arr):
            raise ValueError(
                f"Confidences ({len(confidences_arr)}) and labels ({len(labels_arr)}) "
                f"length mismatch for model {model_name}"
            )

        # For AUC calculation, use confidence-weighted labels
        # by repeating samples proportionally to their confidence
        # (approximation — true weighted AUC is more complex)
        n_positive = int(np.sum(labels_arr))
        n_negative = int(np.sum(~labels_arr.astype(bool)))

        if n_positive == 0 or n_negative == 0:
            roc_auc = 0.5
            pr_auc = 0.0 if n_positive == 0 else 1.0
        else:
            # Weighted AUC: use confidence as sample weights
            try:
                roc_auc = float(
                    roc_auc_score(labels_arr, scores_arr, sample_weight=confidences_arr)
                )
                pr_auc = float(
                    average_precision_score(
                        labels_arr, scores_arr, sample_weight=confidences_arr
                    )
                )
            except ValueError:
                roc_auc = 0.5
                pr_auc = 0.0 if n_positive == 0 else 1.0

        # Build threshold curve with weighted cost
        threshold_curve: list[dict[str, Any]] = []
        best_cost = float("-inf")
        best_cost_threshold = 0.5
        best_f1 = 0.0
        best_f1_threshold = 0.5
        best_youdens_j = -1.0
        best_youdens_threshold = 0.5

        for t in self._thresholds:
            y_pred = (scores_arr >= t).astype(int)

            # Weighted confusion matrix components
            # Each sample contributes its confidence to the relevant cell
            tp_weight = float(
                np.sum(confidences_arr[(labels_arr == 1) & (y_pred == 1)])
            )
            fp_weight = float(
                np.sum(confidences_arr[(labels_arr == 0) & (y_pred == 1)])
            )
            fn_weight = float(
                np.sum(confidences_arr[(labels_arr == 1) & (y_pred == 0)])
            )
            tn_weight = float(
                np.sum(confidences_arr[(labels_arr == 0) & (y_pred == 0)])
            )

            # Unweighted counts for reporting
            tp = int(np.sum((labels_arr == 1) & (y_pred == 1)))
            fp = int(np.sum((labels_arr == 0) & (y_pred == 1)))
            fn = int(np.sum((labels_arr == 1) & (y_pred == 0)))
            tn = int(np.sum((labels_arr == 0) & (y_pred == 0)))

            # Weighted metrics
            prec = (
                tp_weight / (tp_weight + fp_weight)
                if (tp_weight + fp_weight) > 0
                else 0.0
            )
            rec = (
                tp_weight / (tp_weight + fn_weight)
                if (tp_weight + fn_weight) > 0
                else 0.0
            )
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

            # Cost with weighted confusion matrix
            cost = self.cost_matrix.calculate_cost(
                tp_weight, fp_weight, fn_weight, tn_weight
            )

            # Youden's J with weighted rates
            tpr_val = rec
            fpr_val = (
                fp_weight / (fp_weight + tn_weight)
                if (fp_weight + tn_weight) > 0
                else 0.0
            )
            youdens_j = tpr_val - fpr_val

            threshold_curve.append(
                {
                    "threshold": float(t),
                    "precision": prec,
                    "recall": rec,
                    "f1": f1,
                    "cost": cost,
                    "youdens_j": youdens_j,
                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                    "tn": tn,
                    "tp_weighted": tp_weight,
                    "fp_weighted": fp_weight,
                    "fn_weighted": fn_weight,
                    "tn_weighted": tn_weight,
                }
            )

            if cost > best_cost:
                best_cost = cost
                best_cost_threshold = float(t)
            if f1 > best_f1:
                best_f1 = f1
                best_f1_threshold = float(t)
            if youdens_j > best_youdens_j:
                best_youdens_j = youdens_j
                best_youdens_threshold = float(t)

        # Select optimal threshold
        if self.optimization_metric == "f1":
            optimal_threshold = best_f1_threshold
        elif self.optimization_metric == "youdens_j":
            optimal_threshold = best_youdens_threshold
        else:
            optimal_threshold = best_cost_threshold

        # Metrics at optimal threshold (unweighted for reporting)
        y_pred_opt = (scores_arr >= optimal_threshold).astype(int)
        prec_at = float(precision_score(labels_arr, y_pred_opt, zero_division=0))
        rec_at = float(recall_score(labels_arr, y_pred_opt, zero_division=0))
        f1_at = float(f1_score(labels_arr, y_pred_opt, zero_division=0))

        result = TuningResult(
            model_name=model_name,
            optimal_threshold=optimal_threshold,
            precision_at_threshold=prec_at,
            recall_at_threshold=rec_at,
            f1_at_threshold=f1_at,
            pr_auc=pr_auc,
            roc_auc=roc_auc,
            youdens_j=best_youdens_j,
            cost_at_threshold=best_cost,
            threshold_curve=threshold_curve,
            f1_optimal_threshold=best_f1_threshold,
            youdens_optimal_threshold=best_youdens_threshold,
        )

        log.info(
            "model_tuned_weighted",
            model=model_name,
            optimal_threshold=optimal_threshold,
            metric=self.optimization_metric,
            precision=prec_at,
            recall=rec_at,
            f1=f1_at,
            pr_auc=pr_auc,
            roc_auc=roc_auc,
            cost=best_cost,
            avg_confidence=float(np.mean(confidences_arr)),
        )
        return result

    def tune_all_models_weighted(
        self,
        aligned_events: list[AlignedEvent],
        cost_matrix: CostMatrix | None = None,
    ) -> dict[str, TuningResult]:
        """Tune thresholds for all models with confidence-weighted labels.

        Extracts confidence from WeightedAlignedEvent.label_confidence.
        Falls back to confidence=1.0 for regular AlignedEvent (backward compatible).

        Args:
            aligned_events: Aligned events with scores, labels, and optionally
                label_confidence (from WeightedAlignedEvent).
            cost_matrix: Optional override cost matrix.

        Returns:
            Dict mapping model_name → TuningResult.
        """
        cm = cost_matrix or self.cost_matrix

        # Group by model name, extracting confidence if available
        model_groups: dict[str, tuple[list[float], list[bool], list[float]]] = {}
        for ae in aligned_events:
            name = ae.model_name
            if name not in model_groups:
                model_groups[name] = ([], [], [])
            model_groups[name][0].append(ae.score)
            model_groups[name][1].append(ae.label)
            # Extract confidence from WeightedAlignedEvent or default to 1.0
            confidence = getattr(ae, "label_confidence", 1.0)
            model_groups[name][2].append(confidence)

        results: dict[str, TuningResult] = {}
        for model_name, (scores, labels, confidences) in model_groups.items():
            tuner = ThresholdTuner(
                cost_matrix=cm,
                min_threshold=self.min_threshold,
                max_threshold=self.max_threshold,
                threshold_steps=self.threshold_steps,
                optimization_metric=self.optimization_metric,
            )
            results[model_name] = tuner.tune_model_weighted(
                scores, labels, confidences, model_name
            )

        log.info(
            "all_models_tuned_weighted",
            models=list(results.keys()),
            n_events=len(aligned_events),
        )
        return results
