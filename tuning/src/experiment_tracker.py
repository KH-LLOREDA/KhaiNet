"""Experiment tracker: versioning and comparison of tuning experiments.

Each experiment run is saved as a JSON file in ``experiments/{run_id}.json``.
Supports loading, listing, and comparing runs across different configurations
and datasets.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from src.models import ExperimentRun, FusionResult, TuningMetrics, TuningResult

log = structlog.get_logger()


def compute_hash(data: Any) -> str:
    """Compute SHA-256 hash of arbitrary data (dict, list, str).

    Args:
        data: Data to hash (will be JSON-serialized if not a string).

    Returns:
        Hexadecimal SHA-256 hash string.
    """
    if isinstance(data, str):
        content = data.encode()
    else:
        content = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(content).hexdigest()


def compute_dataset_hash(scores: list[Any], labels: list[Any]) -> str:
    """Compute a hash for a dataset (scores + labels).

    Args:
        scores: List of score values.
        labels: List of label values.

    Returns:
        SHA-256 hash string.
    """
    data = {"scores": scores, "labels": labels}
    return compute_hash(data)


class ExperimentTracker:
    """Track, save, and compare tuning experiment runs.

    Args:
        output_dir: Directory to save experiment JSON files.
    """

    def __init__(self, output_dir: str = "./experiments") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def start_run(self, config: dict[str, Any], dataset_hash: str) -> ExperimentRun:
        """Start a new experiment run.

        Args:
            config: Configuration dict used for this run.
            dataset_hash: Hash of the input dataset.

        Returns:
            A new ExperimentRun with config_hash set.
        """
        config_hash = compute_hash(config)
        run = ExperimentRun(
            config_hash=config_hash,
            dataset_hash=dataset_hash,
            timestamp=datetime.now(timezone.utc),
        )
        log.info(
            "experiment_started",
            run_id=run.run_id,
            config_hash=config_hash[:12],
            dataset_hash=dataset_hash[:12],
        )
        return run

    def log_metrics(
        self,
        run: ExperimentRun,
        model_results: list[TuningResult],
        fusion_result: FusionResult,
        metrics: TuningMetrics,
    ) -> ExperimentRun:
        """Attach metrics to an experiment run.

        Args:
            run: The experiment run to update.
            model_results: Per-model tuning results.
            fusion_result: Fusion result.
            metrics: Calculated metrics.

        Returns:
            The updated run (modified in place).
        """
        run.model_results = model_results
        run.fusion_result = fusion_result
        run.metrics = metrics
        return run

    def save_run(self, run: ExperimentRun) -> Path:
        """Save an experiment run to a JSON file.

        Args:
            run: The experiment run to save.

        Returns:
            Path to the saved JSON file.
        """
        filepath = self.output_dir / f"{run.run_id}.json"
        data = run.model_dump(mode="json")
        filepath.write_text(json.dumps(data, indent=2, default=str))
        log.info("experiment_saved", run_id=run.run_id, path=str(filepath))
        return filepath

    def load_run(self, run_id: str) -> ExperimentRun:
        """Load an experiment run from a JSON file.

        Args:
            run_id: The run ID to load.

        Returns:
            The loaded ExperimentRun.

        Raises:
            FileNotFoundError: If the run file doesn't exist.
        """
        filepath = self.output_dir / f"{run_id}.json"
        if not filepath.exists():
            raise FileNotFoundError(f"Experiment run not found: {run_id}")
        data = json.loads(filepath.read_text())
        return ExperimentRun(**data)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all experiment runs with key metrics.

        Returns:
            List of dicts with run_id, timestamp, and key metrics.
        """
        runs: list[dict[str, Any]] = []
        for filepath in sorted(self.output_dir.glob("*.json")):
            try:
                data = json.loads(filepath.read_text())
                entry: dict[str, Any] = {
                    "run_id": data["run_id"],
                    "timestamp": data.get("timestamp", ""),
                    "config_hash": data.get("config_hash", "")[:12],
                    "dataset_hash": data.get("dataset_hash", "")[:12],
                }
                metrics = data.get("metrics")
                if metrics:
                    entry["coverage"] = metrics.get("coverage", 0.0)
                    entry["precision"] = metrics.get("precision", 0.0)
                    entry["advantage"] = metrics.get("advantage", 0)
                    entry["mttd_diff_pct"] = metrics.get("mttd_diff_pct", 0.0)
                fusion = data.get("fusion_result")
                if fusion:
                    entry["fusion_method"] = fusion.get("method", "")
                runs.append(entry)
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("failed_to_load_run", path=str(filepath), error=str(exc))
        return runs

    def compare_runs(self, run_ids: list[str]) -> dict[str, Any]:
        """Compare metrics across multiple runs.

        Args:
            run_ids: List of run IDs to compare.

        Returns:
            Dict with per-run metrics and best run identified.
        """
        comparison: dict[str, Any] = {"runs": {}}
        best_run: str | None = None
        best_score = float("-inf")

        for run_id in run_ids:
            try:
                run = self.load_run(run_id)
                if run.metrics is None:
                    continue
                metrics = run.metrics
                # Composite score: coverage + precision + advantage - |latency_diff|
                score = (
                    metrics.coverage
                    + metrics.precision
                    + metrics.advantage
                    - abs(metrics.mttd_diff_pct)
                )
                comparison["runs"][run_id] = {
                    "coverage": metrics.coverage,
                    "precision": metrics.precision,
                    "advantage": metrics.advantage,
                    "mttd_diff_pct": metrics.mttd_diff_pct,
                    "composite_score": score,
                    "fusion_method": (
                        run.fusion_result.method if run.fusion_result else None
                    ),
                }
                if score > best_score:
                    best_score = score
                    best_run = run_id
            except FileNotFoundError as exc:
                log.warning(
                    "run_not_found_for_comparison", run_id=run_id, error=str(exc)
                )

        comparison["best_run"] = best_run
        comparison["best_score"] = best_score if best_run else None
        return comparison
