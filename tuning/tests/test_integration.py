"""End-to-end integration test for the full tuning pipeline.

Pipeline: generate data → import labels → align → tune thresholds →
fuse scores → calculate metrics → track experiment → check drift.
"""

from __future__ import annotations

import pytest

from src.cost_matrix import CostMatrix
from src.drift_checker import DriftChecker
from src.experiment_tracker import ExperimentTracker, compute_dataset_hash
from src.label_importer import LabelImporter
from src.metrics_calculator import calculate_metrics, gap_analysis
from src.score_fusion import ScoreFusion
from src.synthetic_data import (
    generate_aligned_dataset,
    generate_darktrace_alerts,
    generate_multi_model_scores,
    generate_synthetic_events,
)
from src.temporal_alignment import align_labels_to_events
from src.threshold_tuner import ThresholdTuner


@pytest.fixture
def integration_config():
    return {
        "temporal_alignment": {"window_seconds": 60, "jitter_seconds": 30},
        "cost_matrix": {"fn_cost": 10.0, "fp_cost": 1.0},
        "threshold_tuning": {
            "optimization_metric": "cost_weighted",
            "min_threshold": 0.01,
            "max_threshold": 0.99,
            "threshold_steps": 50,
        },
        "metrics": {
            "targets": {
                "coverage": 90.0,
                "precision": 85.0,
                "advantage": 0,
                "latency_diff_pct": 30.0,
            }
        },
    }


class TestFullPipeline:
    """Full end-to-end pipeline test with synthetic data."""

    def test_pipeline_end_to_end(self, integration_config, tmp_path):
        # Step 1: Generate synthetic data
        scores, labels = generate_synthetic_events(
            n_events=500, anomaly_ratio=0.05, seed=42
        )
        assert len(scores) == 500

        # Step 2: Build supervised labels from the ground truth
        # (simulating Darktrace detecting the same anomalies)
        from datetime import timedelta
        from src.models import SupervisedLabel

        supervised_labels: list[SupervisedLabel] = []
        for score, is_anomaly in zip(scores, labels):
            if is_anomaly:
                # Darktrace detects ~90% of anomalies with small jitter
                import random

                rng = random.Random(hash(score.event_id) % 2**32)
                if rng.random() < 0.9:
                    supervised_labels.append(
                        SupervisedLabel(
                            event_id=f"label-{score.event_id}",
                            timestamp=score.timestamp
                            + timedelta(seconds=rng.uniform(-10, 10)),
                            src_ip=score.src_ip,
                            dst_ip=score.dst_ip,
                            label=True,
                            darktrace_alert_id=f"dt-{score.event_id}",
                            confidence=0.95,
                            event_type="anomaly",
                        )
                    )

        # Step 3: Align labels to events
        aligned = align_labels_to_events(
            labels=supervised_labels,
            events=scores,
            window_seconds=60.0,
            jitter_seconds=30.0,
        )
        assert len(aligned) == 500

        # Step 4: Tune thresholds
        cost_matrix = CostMatrix(fn_cost=10.0, fp_cost=1.0)
        tuner = ThresholdTuner(
            cost_matrix=cost_matrix,
            optimization_metric="cost_weighted",
            threshold_steps=50,
        )
        tuning_results = tuner.tune_all_models(aligned)
        assert len(tuning_results) > 0
        for result in tuning_results.values():
            assert 0.0 < result.optimal_threshold < 1.0
            assert 0.0 <= result.roc_auc <= 1.0

        # Step 5: Fuse scores
        multi_scores, multi_labels = generate_multi_model_scores(
            n_events=200, anomaly_ratio=0.1, seed=42
        )
        fusion = ScoreFusion(method="weighted_average")
        fusion_result = fusion.fuse_scores(multi_scores, multi_labels)
        assert fusion_result.method == "weighted_average"
        assert 0.0 <= fusion_result.unified_score <= 1.0

        # Step 6: Calculate metrics
        # Simulate predictions using the fusion threshold
        import numpy as np

        unified_scores = []
        for i in range(len(multi_labels)):
            event_scores = {m: multi_scores[m][i] for m in multi_scores}
            unified = ScoreFusion.apply_fusion(event_scores, fusion_result)
            unified_scores.append(unified)

        predictions = [s >= fusion_result.threshold for s in unified_scores]
        khainet_latencies = [10.0 + i * 0.1 for i in range(sum(predictions))]
        darktrace_latencies = [12.0 + i * 0.1 for i in range(sum(multi_labels))]

        metrics = calculate_metrics(
            predictions, multi_labels, khainet_latencies, darktrace_latencies
        )
        assert 0.0 <= metrics.coverage <= 100.0
        assert 0.0 <= metrics.precision <= 100.0

        # Step 7: Gap analysis
        gaps = gap_analysis(metrics, integration_config["metrics"]["targets"])
        assert "all_targets_met" in gaps

        # Step 8: Track experiment
        tracker = ExperimentTracker(output_dir=str(tmp_path / "experiments"))
        dataset_hash = compute_dataset_hash([s.score for s in scores], labels)
        run = tracker.start_run(integration_config, dataset_hash)
        tracker.log_metrics(
            run,
            list(tuning_results.values()),
            fusion_result,
            metrics,
        )
        filepath = tracker.save_run(run)
        assert filepath.exists()

        # Verify we can load it back
        loaded = tracker.load_run(run.run_id)
        assert loaded.run_id == run.run_id
        assert loaded.metrics is not None

    def test_pipeline_with_aligned_dataset(self, tmp_path):
        """Pipeline using the pre-aligned dataset generator."""
        # Step 1: Generate aligned dataset
        aligned = generate_aligned_dataset(n_events=300, anomaly_ratio=0.1, seed=42)
        assert len(aligned) == 300

        # Step 2: Tune thresholds
        tuner = ThresholdTuner(threshold_steps=50)
        results = tuner.tune_all_models(aligned)
        assert len(results) > 0

        # Step 3: Calculate metrics from aligned data
        from src.metrics_calculator import calculate_confusion_matrix

        # Use the first model's threshold to make predictions
        first_model = list(results.keys())[0]
        threshold = results[first_model].optimal_threshold

        model_events = [ae for ae in aligned if ae.model_name == first_model]
        predictions = [ae.score >= threshold for ae in model_events]
        labels = [ae.label for ae in model_events]

        cm = calculate_confusion_matrix(predictions, labels)
        assert cm.total_events == len(model_events)

    def test_pipeline_drift_check(self):
        """Drift check after pipeline run."""
        # Reference scores from tuning
        ref_scores, _ = generate_multi_model_scores(
            n_events=200, anomaly_ratio=0.05, seed=42
        )

        # Current scores with potential drift
        current_scores, _ = generate_multi_model_scores(
            n_events=200, anomaly_ratio=0.05, seed=99
        )

        checker = DriftChecker(ref_scores)
        drift_results = checker.check_drift(current_scores)

        assert len(drift_results) == 3
        for model in ref_scores:
            assert model in drift_results
            assert len(drift_results[model]) == 3

        recommendations = checker.recommend_retuning(drift_results)
        assert "needs_retuning" in recommendations

    def test_pipeline_experiment_comparison(self, tmp_path):
        """Compare two experiment runs."""
        tracker = ExperimentTracker(output_dir=str(tmp_path / "experiments"))

        # Run 1
        aligned1 = generate_aligned_dataset(n_events=200, anomaly_ratio=0.1, seed=42)
        tuner = ThresholdTuner(threshold_steps=30)
        results1 = tuner.tune_all_models(aligned1)

        from src.models import ConfusionMatrix, FusionResult, TuningMetrics

        run1 = tracker.start_run({"version": "v1"}, "hash1")
        tracker.log_metrics(
            run1,
            list(results1.values()),
            FusionResult(method="weighted_average", weights={}),
            TuningMetrics(
                coverage=85.0,
                precision=80.0,
                advantage=1,
                confusion_matrix=ConfusionMatrix(),
            ),
        )
        tracker.save_run(run1)

        # Run 2
        run2 = tracker.start_run({"version": "v2"}, "hash2")
        tracker.log_metrics(
            run2,
            list(results1.values()),
            FusionResult(method="stacking", weights={}),
            TuningMetrics(
                coverage=92.0,
                precision=88.0,
                advantage=3,
                confusion_matrix=ConfusionMatrix(),
            ),
        )
        tracker.save_run(run2)

        # Compare
        comparison = tracker.compare_runs([run1.run_id, run2.run_id])
        assert comparison["best_run"] == run2.run_id
        assert len(comparison["runs"]) == 2
