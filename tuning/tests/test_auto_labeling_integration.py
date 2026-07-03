"""Integration test for the auto-labeling pipeline.

Pipeline: generate dataset → generate labels from all sources →
match to events → combine via weak supervision → tune thresholds
(weighted) → select active learning batch → simulate analyst feedback →
re-tune with feedback.
"""

from __future__ import annotations

import pytest

from src.active_learning import ActiveLearningSelector
from src.cost_matrix import CostMatrix
from src.label_sources import (
    AnalystLabeler,
    BrainLabeler,
    MISPLabeler,
    SuricataLabeler,
    WazuhLabeler,
)
from src.models import AnalystFeedback, WeightedAlignedEvent
from src.synthetic_data import generate_auto_labeling_dataset, generate_synthetic_events
from src.temporal_alignment import align_labels_to_events
from src.threshold_tuner import ThresholdTuner
from src.weak_supervisor import WeakSupervisor


class TestAutoLabelingPipeline:
    """Full end-to-end auto-labeling pipeline test."""

    def test_full_pipeline_without_darktrace(self, tmp_path):
        """Complete pipeline using only internal sources (no Darktrace)."""
        # Step 1: Generate synthetic dataset with all source data
        dataset = generate_auto_labeling_dataset(
            n_events=500, anomaly_ratio=0.05, seed=42
        )
        events = dataset["events"]
        ground_truth = dataset["ground_truth"]
        assert len(events) == 500

        # Step 2: Set up label sources (NO Darktrace — isolated environment)
        sources = [
            SuricataLabeler(),
            WazuhLabeler(),
            MISPLabeler(),
            BrainLabeler(),
            AnalystLabeler(),
        ]

        # Step 3: Run weak supervision pipeline
        supervisor = WeakSupervisor(sources=sources)
        source_data = {
            "suricata": dataset["suricata"],
            "wazuh": dataset["wazuh"],
            "misp": dataset["misp"],
            "brain": dataset["brain"],
            "analyst": dataset["analyst"],
        }
        consensus_labels = supervisor.label_events(
            events=events,
            source_data=source_data,
            window_seconds=60.0,
        )

        # Should have labeled some events
        assert len(consensus_labels) > 0
        n_positive = sum(1 for cl in consensus_labels if cl.label)
        n_negative = sum(1 for cl in consensus_labels if not cl.label)
        assert n_positive > 0  # some anomalies detected

        # Step 4: Convert consensus labels to supervised labels and align
        supervised = [cl.to_supervised_label() for cl in consensus_labels]
        aligned = align_labels_to_events(
            labels=supervised,
            events=events,
            window_seconds=60.0,
            jitter_seconds=30.0,
        )
        assert len(aligned) == len(events)

        # Step 5: Build weighted aligned events with confidence
        weighted_aligned: list[WeightedAlignedEvent] = []
        # Create a lookup from event_id to consensus label
        consensus_by_event = {cl.event_id: cl for cl in consensus_labels}
        for ae in aligned:
            cl = consensus_by_event.get(ae.matched_label_id)
            if cl is not None:
                weighted_aligned.append(
                    WeightedAlignedEvent(
                        event=ae.event,
                        label=ae.label,
                        match_distance_seconds=ae.match_distance_seconds,
                        match_confidence=ae.match_confidence,
                        matched_label_id=ae.matched_label_id,
                        label_confidence=cl.confidence,
                        label_source=cl.source,
                        contributing_sources=cl.contributing_sources,
                    )
                )
            else:
                # Unlabeled event — default normal with low confidence
                weighted_aligned.append(
                    WeightedAlignedEvent(
                        event=ae.event,
                        label=False,
                        match_distance_seconds=None,
                        match_confidence=0.0,
                        matched_label_id=None,
                        label_confidence=0.1,  # low confidence for unlabeled
                        label_source="default_normal",
                        contributing_sources=[],
                    )
                )

        # Step 6: Tune thresholds with weighted labels
        tuner = ThresholdTuner(
            cost_matrix=CostMatrix(fn_cost=10.0, fp_cost=1.0),
            threshold_steps=50,
        )
        tuning_results = tuner.tune_all_models_weighted(weighted_aligned)
        assert len(tuning_results) > 0
        for result in tuning_results.values():
            assert 0.0 < result.optimal_threshold < 1.0
            assert 0.0 <= result.roc_auc <= 1.0

        # Step 7: Active learning — select uncertain events for review
        unlabeled = supervisor.get_unlabeled_events(events, consensus_labels)
        selector = ActiveLearningSelector(
            strategy="hybrid", batch_size=10, random_seed=42
        )
        thresholds = {
            name: result.optimal_threshold for name, result in tuning_results.items()
        }

        # Select from unlabeled first (highest priority)
        al_batch = selector.select_from_unlabeled(unlabeled, thresholds)
        assert len(al_batch.queries) <= 10
        assert al_batch.strategy == "unlabeled"

        # Also select by hybrid strategy from all events
        al_batch_hybrid = selector.select_batch(events, thresholds)
        assert len(al_batch_hybrid.queries) == 10

        # Step 8: Simulate analyst feedback on active learning queries
        analyst_feedback: list[AnalystFeedback] = []
        for query in al_batch.queries:
            # Simulate: analyst confirms if score > 0.6 (likely anomaly)
            label = query.unified_score > 0.6
            analyst_feedback.append(
                AnalystFeedback(
                    timestamp=query.timestamp,
                    src_ip=query.src_ip,
                    dst_ip=query.dst_ip,
                    label=label,
                    analyst_id="analyst-test",
                    event_id=query.event_id,
                )
            )

        # Step 9: Re-run pipeline with analyst feedback included
        source_data_with_feedback = dict(source_data)
        source_data_with_feedback["analyst"] = dataset["analyst"] + analyst_feedback
        consensus_with_feedback = supervisor.label_events(
            events=events,
            source_data=source_data_with_feedback,
            window_seconds=60.0,
        )

        # Should have more labels now (analyst feedback added)
        assert len(consensus_with_feedback) >= len(consensus_labels)

    def test_pipeline_weighted_vs_unweighted_tuning(self):
        """Compare weighted vs unweighted threshold tuning."""
        # Generate dataset
        scores, labels = generate_synthetic_events(
            n_events=300, anomaly_ratio=0.1, seed=42
        )

        # Create aligned events
        from src.models import SupervisedLabel
        from datetime import timedelta

        supervised: list[SupervisedLabel] = []
        import random

        rng = random.Random(42)
        for score, is_anomaly in zip(scores, labels):
            if is_anomaly and rng.random() < 0.8:
                supervised.append(
                    SupervisedLabel(
                        event_id=f"label-{score.event_id}",
                        timestamp=score.timestamp
                        + timedelta(seconds=rng.uniform(-10, 10)),
                        src_ip=score.src_ip,
                        dst_ip=score.dst_ip,
                        label=True,
                        confidence=rng.uniform(0.5, 1.0),  # varying confidence
                    )
                )

        aligned = align_labels_to_events(supervised, scores, 60.0, 30.0)

        # Unweighted tuning
        tuner = ThresholdTuner(threshold_steps=50)
        results_unweighted = tuner.tune_all_models(aligned)

        # Weighted tuning (all confidence=1.0 → should match unweighted)
        results_weighted = tuner.tune_all_models_weighted(aligned)

        # With all confidence=1.0, results should be identical
        for model_name in results_unweighted:
            assert (
                results_unweighted[model_name].optimal_threshold
                == results_weighted[model_name].optimal_threshold
            )

    def test_pipeline_source_overlap(self):
        """Test that multiple sources detecting the same event increase confidence."""
        dataset = generate_auto_labeling_dataset(
            n_events=200, anomaly_ratio=0.1, seed=99
        )

        sources = [SuricataLabeler(), MISPLabeler(), BrainLabeler()]
        supervisor = WeakSupervisor(sources=sources)
        source_data = {
            "suricata": dataset["suricata"],
            "misp": dataset["misp"],
            "brain": dataset["brain"],
        }
        consensus = supervisor.label_events(
            events=dataset["events"],
            source_data=source_data,
            window_seconds=60.0,
        )

        # Events detected by multiple sources should have higher confidence
        multi_source = [cl for cl in consensus if len(cl.contributing_sources) > 1]
        single_source = [cl for cl in consensus if len(cl.contributing_sources) == 1]

        if multi_source and single_source:
            avg_multi = sum(cl.confidence for cl in multi_source) / len(multi_source)
            avg_single = sum(cl.confidence for cl in single_source) / len(single_source)
            # Multi-source consensus should generally be more confident
            assert avg_multi >= avg_single * 0.9  # allow some tolerance
