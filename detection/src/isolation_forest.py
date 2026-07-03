"""Isolation Forest detector for network anomaly detection.

Uses scikit-learn's IsolationForest to detect anomalies in network traffic
features. Scores are normalized to 0-1 range where higher = more anomalous.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
from sklearn.ensemble import IsolationForest

from src.feature_engineering import get_feature_matrix
from src.models import FeatureVector, ModelResult

log = structlog.get_logger()


class IsolationForestDetector:
    """Isolation Forest-based anomaly detector.

    Wraps scikit-learn's IsolationForest with score normalization and
    feature importance extraction.

    Attributes:
        n_estimators: Number of trees in the forest.
        contamination: Expected fraction of anomalies ('auto' or float).
        random_state: Random seed for reproducibility.
        threshold: Score threshold above which an event is flagged as anomaly.
        model: The fitted IsolationForest model (None until fit is called).
        scaler: The StandardScaler used during training (None until fit).
        feature_names: Names of features used for training.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: str | float = "auto",
        random_state: int = 42,
        threshold: float = 0.7,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.threshold = threshold
        self.model: IsolationForest | None = None
        self.scaler: Any = None
        self.feature_names: list[str] = []
        self._raw_min: float = 0.0
        self._raw_max: float = 1.0

    def fit(self, features: list[FeatureVector], scaler: Any = None) -> None:
        """Train the Isolation Forest on normalized features.

        Args:
            features: List of FeatureVector objects (normalized field will be
                filled if not already present).
            scaler: Optional pre-fitted StandardScaler. If None, features
                must already have normalized field populated.
        """
        from src.feature_engineering import normalize_features

        if scaler is not None:
            self.scaler = scaler

        # Normalize if not already done
        if features and not features[0].normalized:
            features, self.scaler = normalize_features(features)

        X = get_feature_matrix(features)
        if X.shape[0] == 0:
            log.warning("no_features_to_fit_if")
            return

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        )
        self.model.fit(X)

        # Compute raw score range for normalization
        raw_scores = self.model.score_samples(X)
        self._raw_min = float(np.min(raw_scores))
        self._raw_max = float(np.max(raw_scores))

        # Store feature names
        from src.feature_engineering import ALL_FEATURE_COLUMNS

        self.feature_names = list(ALL_FEATURE_COLUMNS)

        log.info(
            "isolation_forest_fitted",
            n_samples=X.shape[0],
            n_features=X.shape[1],
            raw_min=self._raw_min,
            raw_max=self._raw_max,
        )

    def _normalize_score(self, raw_score: float) -> float:
        """Normalize raw IF score to 0-1 range.

        IsolationForest.score_samples returns negative values where more
        negative = more anomalous. We invert so higher = more anomalous.
        """
        if self._raw_max == self._raw_min:
            return 0.5
        # Invert: more negative raw → higher normalized score
        normalized = (self._raw_max - raw_score) / (self._raw_max - self._raw_min)
        return float(np.clip(normalized, 0.0, 1.0))

    def predict(self, features: list[FeatureVector]) -> list[ModelResult]:
        """Predict anomaly scores for a list of features.

        Args:
            features: List of FeatureVector objects (will be normalized if needed).

        Returns:
            List of ModelResult with scores in 0-1 range.
        """
        if self.model is None:
            log.warning("if_model_not_fitted")
            return []

        # Normalize if needed
        if features and not features[0].normalized and self.scaler is not None:
            from src.feature_engineering import normalize_features

            features, _ = normalize_features(features, self.scaler)

        X = get_feature_matrix(features)
        if X.shape[0] == 0:
            return []

        raw_scores = self.model.score_samples(X)
        results: list[ModelResult] = []

        for i, (vector, raw_score) in enumerate(zip(features, raw_scores)):
            score = self._normalize_score(float(raw_score))
            is_anomaly = score > self.threshold
            results.append(
                ModelResult(
                    model_name="isolation_forest",
                    timestamp=vector.timestamp,
                    src_ip=vector.src_ip,
                    score=score,
                    is_anomaly=is_anomaly,
                    threshold=self.threshold,
                    details={
                        "raw_score": float(raw_score),
                        "dst_ip": vector.dst_ip,
                        "dst_port": vector.dst_port,
                        "bytes_total": vector.bytes_total,
                    },
                )
            )

        log.debug(
            "if_predictions",
            count=len(results),
            n_anomalies=sum(r.is_anomaly for r in results),
        )
        return results

    def get_feature_importance(self) -> dict[str, float]:
        """Get feature importance using impurity-based importance from the underlying trees.

        IsolationForest wraps ExtraTreeRegressor estimators. We aggregate
        their ``feature_importances_`` as a proxy for overall importance.

        Returns:
            Dict mapping feature name to importance score.
        """
        if self.model is None or not self.feature_names:
            return {}

        # IsolationForest stores estimators in .estimators_
        # Each is an ExtraTreeRegressor with feature_importances_
        import numpy as np

        all_importances: list[np.ndarray] = []
        for estimator in self.model.estimators_:
            if hasattr(estimator, "feature_importances_"):
                all_importances.append(estimator.feature_importances_)

        if not all_importances:
            # Fallback: uniform importance
            n = len(self.feature_names)
            return {name: 1.0 / n for name in self.feature_names}

        avg_importance = np.mean(all_importances, axis=0)
        return dict(zip(self.feature_names, [float(x) for x in avg_importance]))
