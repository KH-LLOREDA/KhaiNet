"""Tests for the experiment tracker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.experiment_tracker import (
    ExperimentTracker,
    compute_dataset_hash,
    compute_hash,
)
from src.models import ConfusionMatrix, FusionResult, TuningMetrics, TuningResult


@pytest.fixture
def tracker(tmp_path):
    return ExperimentTracker(output_dir=str(tmp_path / "experiments"))


@pytest.fixture
def sample_tuning_result():
    return TuningResult(
        model_name="isolation_forest",
        optimal_threshold=0.65,
        precision_at_threshold=0.9,
        recall_at_threshold=0.85,
        f1_at_threshold=0.87,
        pr_auc=0.92,
        roc_auc=0.95,
        youdens_j=0.8,
        cost_at_threshold=-5.0,
    )


@pytest.fixture
def sample_fusion_result():
    return FusionResult(
        method="weighted_average",
        weights={"isolation_forest": 0.4, "autoencoder": 0.3, "hmm": 0.3},
        unified_score=0.5,
        threshold=0.5,
    )


@pytest.fixture
def sample_metrics():
    return TuningMetrics(
        coverage=92.0,
        precision=88.0,
        advantage=3,
        mttd_khainet_seconds=15.0,
        mttd_darktrace_seconds=20.0,
        mttd_diff_pct=-25.0,
        confusion_matrix=ConfusionMatrix(
            true_positive=9, false_positive=1, false_negative=1, true_negative=89
        ),
    )


class TestHashFunctions:
    def test_compute_hash_string(self):
        h = compute_hash("test data")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_compute_hash_dict(self):
        h1 = compute_hash({"a": 1, "b": 2})
        h2 = compute_hash({"b": 2, "a": 1})  # Same content, different order
        assert h1 == h2  # sort_keys=True

    def test_compute_hash_different(self):
        h1 = compute_hash({"a": 1})
        h2 = compute_hash({"a": 2})
        assert h1 != h2

    def test_compute_dataset_hash(self):
        h = compute_dataset_hash([0.1, 0.2, 0.3], [True, False, True])
        assert isinstance(h, str)
        assert len(h) == 64


class TestStartRun:
    def test_start_run(self, tracker):
        config = {"model": "test", "threshold": 0.5}
        dataset_hash = compute_dataset_hash([0.1, 0.2], [True, False])
        run = tracker.start_run(config, dataset_hash)
        assert run.run_id is not None
        assert run.config_hash != ""
        assert run.dataset_hash == dataset_hash
        assert run.model_results == []

    def test_config_hash_deterministic(self, tracker):
        config = {"model": "test"}
        dataset_hash = "abc123"
        run1 = tracker.start_run(config, dataset_hash)
        run2 = tracker.start_run(config, dataset_hash)
        assert run1.config_hash == run2.config_hash


class TestLogMetrics:
    def test_log_metrics(
        self, tracker, sample_tuning_result, sample_fusion_result, sample_metrics
    ):
        run = tracker.start_run({"test": True}, "dataset-hash")
        tracker.log_metrics(
            run,
            model_results=[sample_tuning_result],
            fusion_result=sample_fusion_result,
            metrics=sample_metrics,
        )
        assert len(run.model_results) == 1
        assert run.fusion_result is not None
        assert run.metrics is not None
        assert run.metrics.coverage == 92.0


class TestSaveAndLoad:
    def test_save_and_load_run(
        self, tracker, sample_tuning_result, sample_fusion_result, sample_metrics
    ):
        run = tracker.start_run({"test": True}, "dataset-hash")
        tracker.log_metrics(
            run,
            [sample_tuning_result],
            sample_fusion_result,
            sample_metrics,
        )
        filepath = tracker.save_run(run)
        assert filepath.exists()
        assert filepath.suffix == ".json"

        loaded = tracker.load_run(run.run_id)
        assert loaded.run_id == run.run_id
        assert loaded.metrics is not None
        assert loaded.metrics.coverage == 92.0

    def test_load_nonexistent_raises(self, tracker):
        with pytest.raises(FileNotFoundError):
            tracker.load_run("nonexistent-id")


class TestListRuns:
    def test_list_runs(
        self, tracker, sample_tuning_result, sample_fusion_result, sample_metrics
    ):
        run1 = tracker.start_run({"v1": True}, "hash1")
        tracker.log_metrics(
            run1, [sample_tuning_result], sample_fusion_result, sample_metrics
        )
        tracker.save_run(run1)

        run2 = tracker.start_run({"v2": True}, "hash2")
        tracker.log_metrics(
            run2, [sample_tuning_result], sample_fusion_result, sample_metrics
        )
        tracker.save_run(run2)

        runs = tracker.list_runs()
        assert len(runs) == 2
        for entry in runs:
            assert "run_id" in entry
            assert "coverage" in entry
            assert "precision" in entry

    def test_list_empty(self, tracker):
        runs = tracker.list_runs()
        assert runs == []


class TestCompareRuns:
    def test_compare_runs(
        self, tracker, sample_tuning_result, sample_fusion_result, sample_metrics
    ):
        run1 = tracker.start_run({"v1": True}, "hash1")
        metrics1 = TuningMetrics(
            coverage=90.0, precision=85.0, advantage=1, mttd_diff_pct=10.0
        )
        tracker.log_metrics(
            run1, [sample_tuning_result], sample_fusion_result, metrics1
        )
        tracker.save_run(run1)

        run2 = tracker.start_run({"v2": True}, "hash2")
        metrics2 = TuningMetrics(
            coverage=95.0, precision=88.0, advantage=3, mttd_diff_pct=5.0
        )
        tracker.log_metrics(
            run2, [sample_tuning_result], sample_fusion_result, metrics2
        )
        tracker.save_run(run2)

        comparison = tracker.compare_runs([run1.run_id, run2.run_id])
        assert "runs" in comparison
        assert len(comparison["runs"]) == 2
        assert comparison["best_run"] is not None
        # run2 should be better (higher coverage + precision + advantage, lower latency diff)
        assert comparison["best_run"] == run2.run_id

    def test_compare_with_nonexistent(self, tracker):
        comparison = tracker.compare_runs(["nonexistent"])
        assert comparison["best_run"] is None
