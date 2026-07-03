"""Detection pipeline orchestrator.

Coordinates the execution of the 3 detection models (Isolation Forest,
Autoencoder, HMM) and the baseline calculator. Does NOT fuse scores —
that is the responsibility of the tuning/ module. This orchestrator
produces individual scores per model.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from src.autoencoder import AutoencoderDetector
from src.baseline import BaselineCalculator
from src.feature_engineering import (
    ALL_FEATURE_COLUMNS,
    extract_event_features,
    extract_window_features,
    normalize_features,
)
from src.hmm_detector import HMMDetector
from src.isolation_forest import IsolationForestDetector
from src.model_persister import ModelPersister
from src.models import ModelResult, ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL

log = structlog.get_logger()


class DetectionOrchestrator:
    """Coordinate the 3 detection models and baseline.

    The orchestrator:
    1. Extracts features (event-level and window-level)
    2. Trains IF, AE, and HMM
    3. Calculates baseline statistics
    4. Maps HMM states to semantic labels
    5. Produces individual scores per model (no fusion)

    Attributes:
        config: Configuration dict.
        if_detector: Isolation Forest detector.
        ae_detector: Autoencoder detector.
        hmm_detector: HMM detector.
        baseline: Baseline calculator.
        scaler: StandardScaler for feature normalization.
        input_dim: Number of input features.
        feature_columns: Feature column names.
        mock_mode: Whether running in mock mode (no real infrastructure).
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.mock_mode = self.config.get("orchestrator", {}).get("mock_mode", True)

        # Initialize detectors from config
        if_cfg = self.config.get("isolation_forest", {})
        self.if_detector = IsolationForestDetector(
            n_estimators=if_cfg.get("n_estimators", 100),
            contamination=if_cfg.get("contamination", "auto"),
            random_state=if_cfg.get("random_state", 42),
            threshold=if_cfg.get("threshold", 0.7),
        )

        ae_cfg = self.config.get("autoencoder", {})
        self.input_dim = len(ALL_FEATURE_COLUMNS)
        self.ae_detector = AutoencoderDetector(
            input_dim=self.input_dim,
            hidden_dims=ae_cfg.get("hidden_dims", [64, 32, 16]),
            lr=ae_cfg.get("learning_rate", 1e-3),
            epochs=ae_cfg.get("epochs", 50),
            batch_size=ae_cfg.get("batch_size", 32),
            random_state=ae_cfg.get("random_state", 42),
            threshold_percentile=ae_cfg.get("threshold_percentile", 99),
        )

        hmm_cfg = self.config.get("hmm", {})
        self.hmm_detector = HMMDetector(
            n_components=hmm_cfg.get("n_components", 4),
            n_iter=hmm_cfg.get("n_iter", 100),
            random_state=hmm_cfg.get("random_state", 42),
            covariance_type=hmm_cfg.get("covariance_type", "diag"),
        )

        baseline_cfg = self.config.get("baseline", {})
        self.baseline = BaselineCalculator(
            window_hours=baseline_cfg.get("window_hours", 24),
        )

        self.scaler: Any = None
        self.feature_columns = list(ALL_FEATURE_COLUMNS)
        self._is_trained = False

    def train_all(
        self,
        conn_events: list[ZeekConn],
        dns_events: list[ZeekDNS] | None = None,
        http_events: list[ZeekHTTP] | None = None,
        ssl_events: list[ZeekSSL] | None = None,
    ) -> dict[str, Any]:
        """Train all models and calculate baseline.

        Pipeline:
        1. Feature engineering (event features + window features)
        2. Normalize features
        3. Train Isolation Forest
        4. Train Autoencoder
        5. Train HMM
        6. Calculate baseline
        7. Map HMM states

        Args:
            conn_events: Connection events.
            dns_events: DNS events.
            http_events: HTTP events.
            ssl_events: SSL events.

        Returns:
            Training summary dict.
        """
        dns_events = dns_events or []
        http_events = http_events or []
        ssl_events = ssl_events or []

        log.info("training_all_models", conn=len(conn_events), dns=len(dns_events))

        # 1. Feature engineering
        event_features = extract_event_features(
            conn_events, dns_events, http_events, ssl_events
        )

        fe_cfg = self.config.get("feature_engineering", {})
        window_minutes = fe_cfg.get("window_minutes", 5)
        window_features = extract_window_features(
            conn_events, dns_events, window_minutes=window_minutes
        )

        # 2. Normalize features
        event_features, self.scaler = normalize_features(event_features)
        self.input_dim = (
            len(event_features[0].normalized) if event_features else self.input_dim
        )

        # 3. Train Isolation Forest
        if event_features:
            self.if_detector.fit(event_features, self.scaler)

        # 4. Train Autoencoder
        if event_features:
            self.ae_detector.fit(event_features, self.scaler)

        # 5. Train HMM
        if window_features:
            self.hmm_detector.fit(window_features)

        # 6. Calculate baseline
        self.baseline.calculate_baseline(conn_events, dns_events)

        # 7. Map HMM states
        if self.hmm_detector.model is not None:
            self.hmm_detector.map_states(self.baseline)

        self._is_trained = True

        summary: dict[str, Any] = {
            "n_conn_events": len(conn_events),
            "n_dns_events": len(dns_events),
            "n_event_features": len(event_features),
            "n_window_features": len(window_features),
            "if_trained": self.if_detector.model is not None,
            "ae_trained": self.ae_detector.model is not None,
            "hmm_trained": self.hmm_detector.model is not None,
            "baseline_stats": len(self.baseline.stats),
            "hmm_state_mappings": len(self.hmm_detector.state_mappings),
            "input_dim": self.input_dim,
        }
        log.info("training_complete", **summary)
        return summary

    def detect(
        self,
        conn_events: list[ZeekConn],
        dns_events: list[ZeekDNS] | None = None,
        http_events: list[ZeekHTTP] | None = None,
        ssl_events: list[ZeekSSL] | None = None,
    ) -> list[ModelResult]:
        """Run all 3 models and produce individual scores.

        Does NOT fuse scores — returns individual ModelResult per model.

        Args:
            conn_events: Connection events.
            dns_events: DNS events.
            http_events: HTTP events.
            ssl_events: SSL events.

        Returns:
            List of ModelResult from all 3 models combined.
        """
        dns_events = dns_events or []
        http_events = http_events or []
        ssl_events = ssl_events or []

        # Feature engineering
        event_features = extract_event_features(
            conn_events, dns_events, http_events, ssl_events
        )

        fe_cfg = self.config.get("feature_engineering", {})
        window_minutes = fe_cfg.get("window_minutes", 5)
        window_features = extract_window_features(
            conn_events, dns_events, window_minutes=window_minutes
        )

        # Normalize using existing scaler
        if self.scaler is not None:
            from src.feature_engineering import normalize_features

            event_features, _ = normalize_features(event_features, self.scaler)

        all_results: list[ModelResult] = []

        # IF predictions
        if self.if_detector.model is not None:
            if_results = self.if_detector.predict(event_features)
            all_results.extend(if_results)

        # AE predictions
        if self.ae_detector.model is not None:
            ae_results = self.ae_detector.predict(event_features)
            all_results.extend(ae_results)

        # HMM predictions
        if self.hmm_detector.model is not None:
            hmm_results = self.hmm_detector.predict(window_features)
            all_results.extend(hmm_results)

        log.info(
            "detection_complete",
            total_results=len(all_results),
            if_results=sum(
                1 for r in all_results if r.model_name == "isolation_forest"
            ),
            ae_results=sum(1 for r in all_results if r.model_name == "autoencoder"),
            hmm_results=sum(1 for r in all_results if r.model_name == "hmm"),
        )
        return all_results

    def save_models(self, path: str | Path) -> None:
        """Save all trained models to a directory."""
        ModelPersister.save_all(self, path)

    def load_models(self, path: str | Path) -> None:
        """Load all models from a directory."""
        loaded = ModelPersister.load_all(path)

        if "if_detector" in loaded:
            self.if_detector = loaded["if_detector"]
        if "ae_detector" in loaded:
            self.ae_detector = loaded["ae_detector"]
        if "hmm_detector" in loaded:
            self.hmm_detector = loaded["hmm_detector"]
        if "baseline" in loaded:
            self.baseline = loaded["baseline"]
        if "scaler" in loaded:
            self.scaler = loaded["scaler"]
        if "meta" in loaded:
            meta = loaded["meta"]
            self.input_dim = meta.get("input_dim", self.input_dim)
            self.feature_columns = meta.get("feature_columns", self.feature_columns)

        self._is_trained = True
        log.info("models_loaded", path=str(path))
