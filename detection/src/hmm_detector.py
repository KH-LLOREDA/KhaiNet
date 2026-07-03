"""HMM detector for network anomaly detection.

Uses hmmlearn's GaussianHMM with 4 hidden states. States are unsupervised —
the mapping to semantic labels (normal, scan, exfil, c2) is done in
post-training by comparing state means against the baseline.

Observation features: [bytes_out, unique_destinations, pkts_total,
                       nxdomain_ratio, avg_duration] (5 features).
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

import numpy as np
import structlog
from hmmlearn.hmm import GaussianHMM

from src.models import ModelResult, StateMapping, WindowFeatures

if TYPE_CHECKING:
    from src.baseline import BaselineCalculator

log = structlog.get_logger()

# Observation features for the HMM
HMM_FEATURE_COLUMNS = [
    "bytes_out",
    "unique_destinations",
    "pkts_total",
    "nxdomain_ratio",
    "avg_duration",
]

# Semantic labels for states
STATE_LABELS = ["normal", "scan", "exfil", "c2"]


class HMMDetector:
    """Hidden Markov Model-based anomaly detector.

    Uses a GaussianHMM with 4 hidden states. The model learns temporal
    patterns in windowed traffic features. States are mapped to semantic
    labels (normal, scan, exfil, c2) in post-training.

    Attributes:
        n_components: Number of hidden states (default 4).
        n_iter: Maximum EM iterations.
        random_state: Random seed.
        covariance_type: Type of covariance matrix ('diag', 'full', etc.).
        model: The fitted GaussianHMM.
        state_mappings: Mapping from state ID to semantic label.
        threshold: Score threshold for anomaly flagging.
    """

    def __init__(
        self,
        n_components: int = 4,
        n_iter: int = 100,
        random_state: int = 42,
        covariance_type: str = "diag",
        threshold: float = 0.5,
    ):
        self.n_components = n_components
        self.n_iter = n_iter
        self.random_state = random_state
        self.covariance_type = covariance_type
        self.threshold = threshold
        self.model: GaussianHMM | None = None
        self.state_mappings: list[StateMapping] = []
        self._normal_state: int = 0
        self._feature_columns = list(HMM_FEATURE_COLUMNS)

    def _window_to_array(self, wf: WindowFeatures) -> np.ndarray:
        """Convert a WindowFeatures object to an observation array."""
        return np.array([[float(getattr(wf, col)) for col in self._feature_columns]])

    def _build_sequences(
        self, window_features: list[WindowFeatures]
    ) -> tuple[np.ndarray, list[int]]:
        """Group window features by src_ip and build sequences.

        Returns:
            Tuple of (concatenated observations, list of sequence lengths).
        """
        by_host: dict[str, list[WindowFeatures]] = defaultdict(list)
        for wf in window_features:
            by_host[wf.src_ip].append(wf)

        # Sort each host's windows by timestamp
        for host in by_host:
            by_host[host].sort(key=lambda w: w.window_start)

        all_obs: list[np.ndarray] = []
        lengths: list[int] = []

        for host, windows in by_host.items():
            if len(windows) < 2:
                continue
            obs = np.array(
                [
                    [float(getattr(w, col)) for col in self._feature_columns]
                    for w in windows
                ]
            )
            all_obs.append(obs)
            lengths.append(len(obs))

        if not all_obs:
            return np.array([]).reshape(0, len(self._feature_columns)), []

        X = np.vstack(all_obs)
        return X, lengths

    def fit(self, window_features: list[WindowFeatures]) -> None:
        """Train the HMM on windowed features.

        Groups windows by src_ip into sequences and trains a GaussianHMM.

        Args:
            window_features: List of WindowFeatures objects.
        """
        X, lengths = self._build_sequences(window_features)

        if X.shape[0] == 0 or len(lengths) < 1:
            log.warning("no_sequences_to_fit_hmm")
            return

        # Ensure we have enough data for the number of components
        if X.shape[0] < self.n_components:
            log.warning(
                "insufficient_data_for_hmm",
                n_samples=X.shape[0],
                n_components=self.n_components,
            )
            return

        self.model = GaussianHMM(
            n_components=self.n_components,
            n_iter=self.n_iter,
            covariance_type=self.covariance_type,
            random_state=self.random_state,
        )

        try:
            self.model.fit(X, lengths)
        except Exception as exc:
            log.warning("hmm_fit_failed", error=str(exc))
            # Try with fewer iterations or different covariance
            self.model = GaussianHMM(
                n_components=self.n_components,
                n_iter=min(self.n_iter, 10),
                covariance_type="diag",
                random_state=self.random_state,
            )
            self.model.fit(X, lengths)

        log.info(
            "hmm_fitted",
            n_samples=X.shape[0],
            n_sequences=len(lengths),
            n_components=self.n_components,
        )

    def map_states(self, baseline: BaselineCalculator) -> list[StateMapping]:
        """Map HMM states to semantic labels using baseline statistics.

        Post-training mapping:
        - State with lowest bytes_out and fewest destinations → normal
        - State with most unique destinations → scan
        - State with highest bytes_out → exfil
        - Remaining state → c2 (regularity-based)

        Args:
            baseline: BaselineCalculator with computed statistics.

        Returns:
            List of StateMapping objects.
        """
        if self.model is None:
            log.warning("hmm_not_fitted_for_mapping")
            return []

        means = self.model.means_  # shape: (n_components, n_features)
        n_states = self.n_components

        # Feature indices
        idx_bytes_out = self._feature_columns.index("bytes_out")
        idx_unique_dsts = self._feature_columns.index("unique_destinations")

        # Score each state for each label
        state_scores: list[dict[str, float]] = []
        for s in range(n_states):
            state_means = means[s]
            scores = {
                "normal": -state_means[idx_bytes_out]
                - state_means[idx_unique_dsts] * 1000,
                "scan": state_means[idx_unique_dsts],
                "exfil": state_means[idx_bytes_out],
                "c2": 0.0,  # fallback
            }
            state_scores.append(scores)

        # Assign labels greedily: best state for each label
        assigned: dict[int, str] = {}
        used_states: set[int] = set()

        # Assign in priority order: exfil (highest bytes), scan (most dsts), normal (lowest), c2 (rest)
        label_priority = ["exfil", "scan", "normal", "c2"]

        for label in label_priority:
            if len(used_states) >= n_states:
                break
            best_state = -1
            best_score = float("-inf")
            for s in range(n_states):
                if s in used_states:
                    continue
                if state_scores[s][label] > best_score:
                    best_score = state_scores[s][label]
                    best_state = s
            if best_state >= 0:
                assigned[best_state] = label
                used_states.add(best_state)

        # Assign remaining states to c2
        for s in range(n_states):
            if s not in assigned:
                assigned[s] = "c2"

        # Find normal state
        self._normal_state = next(
            (s for s, label in assigned.items() if label == "normal"), 0
        )

        # Build StateMapping objects
        mappings: list[StateMapping] = []
        for s in range(n_states):
            label = assigned[s]
            mean_features = {
                col: float(means[s][i]) for i, col in enumerate(self._feature_columns)
            }
            # Confidence based on how clearly the state matches its label
            confidence = 0.5 + 0.5 * (
                abs(state_scores[s][label]) / (abs(state_scores[s][label]) + 1e-10)
            )
            confidence = float(np.clip(confidence, 0.0, 1.0))
            mappings.append(
                StateMapping(
                    state_id=s,
                    label=label,
                    confidence=confidence,
                    mean_features=mean_features,
                )
            )

        self.state_mappings = mappings
        log.info(
            "hmm_states_mapped", mappings=[(m.state_id, m.label) for m in mappings]
        )
        return mappings

    def predict(self, window_features: list[WindowFeatures]) -> list[ModelResult]:
        """Predict anomaly scores for windowed features.

        For each window, compute the log-likelihood under the HMM.
        States that are not 'normal' or transitions to anomalous states
        produce higher scores.

        Args:
            window_features: List of WindowFeatures objects.

        Returns:
            List of ModelResult with scores in 0-1 range.
        """
        if self.model is None:
            log.warning("hmm_not_fitted_for_prediction")
            return []

        # Build label lookup
        label_map = {m.state_id: m.label for m in self.state_mappings}

        results: list[ModelResult] = []
        by_host: dict[str, list[WindowFeatures]] = defaultdict(list)
        for wf in window_features:
            by_host[wf.src_ip].append(wf)

        for host, windows in by_host.items():
            windows.sort(key=lambda w: w.window_start)
            if len(windows) < 1:
                continue

            obs = np.array(
                [
                    [float(getattr(w, col)) for col in self._feature_columns]
                    for w in windows
                ]
            )

            try:
                # Get state predictions
                states = self.model.predict(obs)
                # Get log-likelihood
                log_likelihood = self.model.score(obs)
            except Exception:
                states = np.zeros(len(windows), dtype=int)
                log_likelihood = 0.0

            # Compute per-window scores
            for i, wf in enumerate(windows):
                state = int(states[i])
                label = label_map.get(state, "unknown")

                # Score based on state: non-normal states get higher scores
                if label == "normal":
                    base_score = 0.1
                elif label == "scan":
                    base_score = 0.6
                elif label == "exfil":
                    base_score = 0.8
                elif label == "c2":
                    base_score = 0.7
                else:
                    base_score = 0.5

                # Adjust based on log-likelihood (lower = more anomalous)
                ll_adjustment = max(0.0, min(0.2, -log_likelihood / 100))
                score = float(np.clip(base_score + ll_adjustment, 0.0, 1.0))

                is_anomaly = score > self.threshold or label != "normal"

                results.append(
                    ModelResult(
                        model_name="hmm",
                        timestamp=wf.timestamp,
                        src_ip=wf.src_ip,
                        score=score,
                        is_anomaly=is_anomaly,
                        threshold=self.threshold,
                        details={
                            "state": state,
                            "state_label": label,
                            "log_likelihood": float(log_likelihood),
                            "window_start": wf.window_start.isoformat(),
                            "connection_count": wf.connection_count,
                        },
                    )
                )

        log.debug(
            "hmm_predictions",
            count=len(results),
            n_anomalies=sum(r.is_anomaly for r in results),
        )
        return results

    def get_state_transitions(self) -> np.ndarray | None:
        """Get the state transition probability matrix.

        Returns:
            Matrix of shape (n_components, n_components) or None.
        """
        if self.model is None:
            return None
        return self.model.transmat_
