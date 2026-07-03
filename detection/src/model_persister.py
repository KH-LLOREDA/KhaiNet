"""Model persistence for detection models.

Saves and loads trained models using:
- joblib for Isolation Forest and HMM (scikit-learn compatible)
- torch.save for Autoencoder (state_dict + config)
- JSON for Baseline (serializable stats)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib
import structlog
import torch

if TYPE_CHECKING:
    from src.autoencoder import AutoencoderDetector
    from src.baseline import BaselineCalculator
    from src.hmm_detector import HMMDetector
    from src.isolation_forest import IsolationForestDetector
    from src.orchestrator import DetectionOrchestrator

log = structlog.get_logger()


class ModelPersister:
    """Persist and load trained detection models.

    All methods are static. Models are saved to individual files, with
    ``save_all`` / ``load_all`` for batch operations.
    """

    @staticmethod
    def save_if(model: IsolationForestDetector, path: str | Path) -> None:
        """Save an Isolation Forest detector using joblib."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": model.model,
                "scaler": model.scaler,
                "threshold": model.threshold,
                "n_estimators": model.n_estimators,
                "contamination": model.contamination,
                "random_state": model.random_state,
                "feature_names": model.feature_names,
                "raw_min": model._raw_min,
                "raw_max": model._raw_max,
            },
            path,
        )
        log.debug("if_model_saved", path=str(path))

    @staticmethod
    def load_if(path: str | Path) -> IsolationForestDetector:
        """Load an Isolation Forest detector from joblib."""
        from src.isolation_forest import IsolationForestDetector

        data = joblib.load(path)
        detector = IsolationForestDetector(
            n_estimators=data.get("n_estimators", 100),
            contamination=data.get("contamination", "auto"),
            random_state=data.get("random_state", 42),
            threshold=data.get("threshold", 0.7),
        )
        detector.model = data["model"]
        detector.scaler = data["scaler"]
        detector.feature_names = data.get("feature_names", [])
        detector._raw_min = data.get("raw_min", 0.0)
        detector._raw_max = data.get("raw_max", 1.0)
        log.debug("if_model_loaded", path=str(path))
        return detector

    @staticmethod
    def save_ae(model: AutoencoderDetector, path: str | Path) -> None:
        """Save an Autoencoder detector using torch.save."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        state = model.get_state_dict()
        torch.save(state, path)
        log.debug("ae_model_saved", path=str(path))

    @staticmethod
    def load_ae(path: str | Path, input_dim: int) -> AutoencoderDetector:
        """Load an Autoencoder detector from torch.save."""
        from src.autoencoder import AutoencoderDetector

        state = torch.load(path, weights_only=False)
        detector = AutoencoderDetector(
            input_dim=state.get("input_dim", input_dim),
            hidden_dims=state.get("hidden_dims", [64, 32, 16]),
            lr=state.get("lr", 1e-3),
            epochs=state.get("epochs", 50),
            batch_size=state.get("batch_size", 32),
            random_state=state.get("random_state", 42),
            threshold_percentile=state.get("threshold_percentile", 99),
        )
        detector.load_state_dict(state)
        log.debug("ae_model_loaded", path=str(path))
        return detector

    @staticmethod
    def save_hmm(model: HMMDetector, path: str | Path) -> None:
        """Save an HMM detector using joblib."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": model.model,
                "n_components": model.n_components,
                "n_iter": model.n_iter,
                "random_state": model.random_state,
                "covariance_type": model.covariance_type,
                "threshold": model.threshold,
                "state_mappings": [
                    m.model_dump(mode="json") for m in model.state_mappings
                ],
                "normal_state": model._normal_state,
                "feature_columns": model._feature_columns,
            },
            path,
        )
        log.debug("hmm_model_saved", path=str(path))

    @staticmethod
    def load_hmm(path: str | Path) -> HMMDetector:
        """Load an HMM detector from joblib."""
        from src.hmm_detector import HMMDetector
        from src.models import StateMapping

        data = joblib.load(path)
        detector = HMMDetector(
            n_components=data.get("n_components", 4),
            n_iter=data.get("n_iter", 100),
            random_state=data.get("random_state", 42),
            covariance_type=data.get("covariance_type", "diag"),
            threshold=data.get("threshold", 0.5),
        )
        detector.model = data["model"]
        detector.state_mappings = [
            StateMapping(**m) for m in data.get("state_mappings", [])
        ]
        detector._normal_state = data.get("normal_state", 0)
        detector._feature_columns = data.get("feature_columns", [])
        log.debug("hmm_model_loaded", path=str(path))
        return detector

    @staticmethod
    def save_baseline(baseline: BaselineCalculator, path: str | Path) -> None:
        """Save a baseline calculator as JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = baseline.to_dict()
        path.write_text(json.dumps(data, indent=2, default=str))
        log.debug("baseline_saved", path=str(path))

    @staticmethod
    def load_baseline(path: str | Path) -> BaselineCalculator:
        """Load a baseline calculator from JSON."""
        from src.baseline import BaselineCalculator

        path = Path(path)
        data = json.loads(path.read_text())
        calc = BaselineCalculator.from_dict(data)
        log.debug("baseline_loaded", path=str(path))
        return calc

    @staticmethod
    def save_all(orchestrator: DetectionOrchestrator, dir_path: str | Path) -> None:
        """Save all models from an orchestrator to a directory.

        Saves:
        - isolation_forest.joblib
        - autoencoder.pt
        - hmm.joblib
        - baseline.json
        - scaler.joblib (the feature scaler)
        - meta.json (metadata about the models)

        Args:
            orchestrator: DetectionOrchestrator with trained models.
            dir_path: Directory to save models to.
        """
        dir_path = Path(dir_path)
        dir_path.mkdir(parents=True, exist_ok=True)

        if orchestrator.if_detector and orchestrator.if_detector.model:
            ModelPersister.save_if(
                orchestrator.if_detector, dir_path / "isolation_forest.joblib"
            )

        if orchestrator.ae_detector and orchestrator.ae_detector.model:
            ModelPersister.save_ae(
                orchestrator.ae_detector, dir_path / "autoencoder.pt"
            )

        if orchestrator.hmm_detector and orchestrator.hmm_detector.model:
            ModelPersister.save_hmm(orchestrator.hmm_detector, dir_path / "hmm.joblib")

        if orchestrator.baseline and orchestrator.baseline.stats:
            ModelPersister.save_baseline(
                orchestrator.baseline, dir_path / "baseline.json"
            )

        # Save scaler
        if orchestrator.scaler is not None:
            joblib.dump(orchestrator.scaler, dir_path / "scaler.joblib")

        # Save metadata
        meta: dict[str, Any] = {
            "input_dim": orchestrator.input_dim,
            "feature_columns": orchestrator.feature_columns,
            "has_if": orchestrator.if_detector is not None
            and orchestrator.if_detector.model is not None,
            "has_ae": orchestrator.ae_detector is not None
            and orchestrator.ae_detector.model is not None,
            "has_hmm": orchestrator.hmm_detector is not None
            and orchestrator.hmm_detector.model is not None,
            "has_baseline": orchestrator.baseline is not None
            and len(orchestrator.baseline.stats) > 0,
        }
        (dir_path / "meta.json").write_text(json.dumps(meta, indent=2))
        log.info("all_models_saved", dir=str(dir_path))

    @staticmethod
    def load_all(dir_path: str | Path) -> dict[str, Any]:
        """Load all models from a directory.

        Args:
            dir_path: Directory containing saved models.

        Returns:
            Dict with keys: if_detector, ae_detector, hmm_detector,
            baseline, scaler, meta.
        """
        dir_path = Path(dir_path)

        result: dict[str, Any] = {}

        # Load metadata
        meta_path = dir_path / "meta.json"
        if meta_path.exists():
            result["meta"] = json.loads(meta_path.read_text())
        else:
            result["meta"] = {}

        # Load IF
        if_path = dir_path / "isolation_forest.joblib"
        if if_path.exists():
            result["if_detector"] = ModelPersister.load_if(if_path)

        # Load AE
        ae_path = dir_path / "autoencoder.pt"
        if ae_path.exists():
            input_dim = result.get("meta", {}).get("input_dim", 17)
            result["ae_detector"] = ModelPersister.load_ae(ae_path, input_dim)

        # Load HMM
        hmm_path = dir_path / "hmm.joblib"
        if hmm_path.exists():
            result["hmm_detector"] = ModelPersister.load_hmm(hmm_path)

        # Load baseline
        baseline_path = dir_path / "baseline.json"
        if baseline_path.exists():
            result["baseline"] = ModelPersister.load_baseline(baseline_path)

        # Load scaler
        scaler_path = dir_path / "scaler.joblib"
        if scaler_path.exists():
            result["scaler"] = joblib.load(scaler_path)

        log.info("all_models_loaded", dir=str(dir_path), keys=list(result.keys()))
        return result
