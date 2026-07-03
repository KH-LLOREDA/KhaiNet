"""Cost matrix for threshold optimization in cybersecurity anomaly detection.

In cybersecurity, a false negative (missing an attack) is far more costly
than a false positive (a false alarm). The default cost ratio is 10:1
(FN costs 10× more than FP).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import structlog

log = structlog.get_logger()


@dataclass
class CostMatrix:
    """Cost matrix for cost-weighted threshold optimization.

    The total cost is calculated as:
        cost = tp * tp_benefit + tn * tn_benefit - fp * fp_cost - fn * fn_cost

    Defaults: fn_cost=10, fp_cost=1 (FN is 10× more expensive than FP).
    """

    fn_cost: float = 10.0
    fp_cost: float = 1.0
    tp_benefit: float = 0.0
    tn_benefit: float = 0.0

    def calculate_cost(self, tp: int, fp: int, fn: int, tn: int) -> float:
        """Calculate the total cost for a confusion matrix.

        A lower (more negative) cost is worse; a higher cost is better.
        Since FN and FP are subtracted, maximizing this score minimizes
        the total penalty.

        Args:
            tp: True positives.
            fp: False positives.
            fn: False negatives.
            tn: True negatives.

        Returns:
            The cost-weighted score (higher is better).
        """
        cost = (
            tp * self.tp_benefit
            + tn * self.tn_benefit
            - fp * self.fp_cost
            - fn * self.fn_cost
        )
        return float(cost)

    def cost_weighted_score(
        self, y_true: list[bool] | np.ndarray, y_pred: list[bool] | np.ndarray
    ) -> float:
        """Calculate cost-weighted score from true and predicted labels.

        Args:
            y_true: Ground-truth labels.
            y_pred: Predicted labels (threshold applied).

        Returns:
            Cost-weighted score (higher is better).
        """
        y_true_arr = np.asarray(y_true, dtype=bool)
        y_pred_arr = np.asarray(y_pred, dtype=bool)

        tp = int(np.sum(y_true_arr & y_pred_arr))
        fp = int(np.sum(~y_true_arr & y_pred_arr))
        fn = int(np.sum(y_true_arr & ~y_pred_arr))
        tn = int(np.sum(~y_true_arr & ~y_pred_arr))

        return self.calculate_cost(tp, fp, fn, tn)

    def cost_at_threshold(
        self,
        scores: list[float] | np.ndarray,
        labels: list[bool] | np.ndarray,
        threshold: float,
    ) -> float:
        """Calculate cost-weighted score at a specific threshold.

        Args:
            scores: Model scores (0-1).
            labels: Ground-truth labels.
            threshold: Decision threshold.

        Returns:
            Cost-weighted score (higher is better).
        """
        scores_arr = np.asarray(scores, dtype=float)
        y_pred = scores_arr >= threshold
        return self.cost_weighted_score(labels, y_pred)

    def find_optimal_threshold(
        self,
        scores: list[float] | np.ndarray,
        labels: list[bool] | np.ndarray,
        thresholds: list[float] | np.ndarray | None = None,
    ) -> tuple[float, float]:
        """Find the threshold that maximizes the cost-weighted score.

        Args:
            scores: Model scores (0-1).
            labels: Ground-truth labels.
            thresholds: Optional list of thresholds to evaluate. If None,
                uses 100 evenly spaced thresholds from 0.01 to 0.99.

        Returns:
            Tuple of (optimal_threshold, best_cost_score).
        """
        scores_arr = np.asarray(scores, dtype=float)
        if thresholds is None:
            thresholds = np.linspace(0.01, 0.99, 100)

        best_threshold = 0.5
        best_cost = float("-inf")

        for t in thresholds:
            cost = self.cost_at_threshold(scores_arr, labels, t)
            if cost > best_cost:
                best_cost = cost
                best_threshold = float(t)

        log.debug(
            "optimal_threshold_found",
            threshold=best_threshold,
            cost=best_cost,
            fn_cost=self.fn_cost,
            fp_cost=self.fp_cost,
        )
        return best_threshold, best_cost
