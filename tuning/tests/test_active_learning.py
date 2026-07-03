"""Tests for the active learning selector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.active_learning import ActiveLearningSelector
from src.models import ModelScore


@pytest.fixture
def sample_events(now_utc, src_ip_a, dst_ip_a) -> list[ModelScore]:
    """20 events: some clearly anomalous, some clearly normal, some uncertain."""
    events: list[ModelScore] = []
    # 5 clearly normal (low scores from all models)
    for i in range(5):
        for model in ["isolation_forest", "autoencoder", "hmm"]:
            events.append(
                ModelScore(
                    event_id=f"evt-normal-{i}",
                    timestamp=now_utc + timedelta(seconds=i),
                    src_ip=src_ip_a,
                    dst_ip=dst_ip_a,
                    model_name=model,
                    score=0.1 + i * 0.02,
                )
            )
    # 5 clearly anomalous (high scores from all models)
    for i in range(5):
        for model in ["isolation_forest", "autoencoder", "hmm"]:
            events.append(
                ModelScore(
                    event_id=f"evt-anom-{i}",
                    timestamp=now_utc + timedelta(seconds=100 + i),
                    src_ip=src_ip_a,
                    dst_ip=dst_ip_a,
                    model_name=model,
                    score=0.85 + i * 0.02,
                )
            )
    # 5 uncertain (scores near threshold 0.5)
    for i in range(5):
        for model in ["isolation_forest", "autoencoder", "hmm"]:
            events.append(
                ModelScore(
                    event_id=f"evt-uncertain-{i}",
                    timestamp=now_utc + timedelta(seconds=200 + i),
                    src_ip=src_ip_a,
                    dst_ip=dst_ip_a,
                    model_name=model,
                    score=0.45 + i * 0.02,  # 0.45 to 0.53
                )
            )
    # 5 disagreement (models disagree)
    for i in range(5):
        events.append(
            ModelScore(
                event_id=f"evt-disagree-{i}",
                timestamp=now_utc + timedelta(seconds=300 + i),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.8,
            )
        )
        events.append(
            ModelScore(
                event_id=f"evt-disagree-{i}",
                timestamp=now_utc + timedelta(seconds=300 + i),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="autoencoder",
                score=0.2,
            )
        )
        events.append(
            ModelScore(
                event_id=f"evt-disagree-{i}",
                timestamp=now_utc + timedelta(seconds=300 + i),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="hmm",
                score=0.5,
            )
        )
    return events


class TestUncertaintySampling:
    def test_selects_events_near_threshold(self, sample_events):
        selector = ActiveLearningSelector(
            strategy="uncertainty", batch_size=5, random_seed=42
        )
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}
        batch = selector.select_batch(sample_events, thresholds)

        assert len(batch.queries) == 5
        # All selected events should have high uncertainty scores
        # (scores near the threshold 0.5)
        for query in batch.queries:
            assert query.uncertainty_score > 0.5
        # Verify that events far from threshold are NOT selected
        selected_ids = {q.event_id for q in batch.queries}
        normal_selected = {eid for eid in selected_ids if "normal" in eid}
        anom_selected = {eid for eid in selected_ids if "anom" in eid}
        # Clearly normal/anomalous events should not be selected by uncertainty
        assert len(normal_selected) == 0
        assert len(anom_selected) == 0

    def test_uncertainty_score_highest_at_threshold(self):
        selector = ActiveLearningSelector(strategy="uncertainty")
        # Score at threshold → uncertainty = 1.0
        assert selector._uncertainty_score(0.5, 0.5) == pytest.approx(1.0)
        # Score far from threshold → low uncertainty
        assert selector._uncertainty_score(0.1, 0.5) < 0.1
        assert selector._uncertainty_score(0.9, 0.5) < 0.1


class TestDisagreementSampling:
    def test_selects_events_with_model_disagreement(self, sample_events):
        selector = ActiveLearningSelector(
            strategy="disagreement", batch_size=5, random_seed=42
        )
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}
        batch = selector.select_batch(sample_events, thresholds)

        assert len(batch.queries) == 5
        # Disagreement events should be prioritized
        selected_ids = {q.event_id for q in batch.queries}
        disagree_selected = {eid for eid in selected_ids if "disagree" in eid}
        assert len(disagree_selected) > 0

    def test_disagreement_score(self, sample_events):
        selector = ActiveLearningSelector(strategy="disagreement")
        # Events with same scores → low disagreement
        agree_events = [
            ModelScore(
                event_id="evt-1",
                timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc),
                src_ip="a",
                dst_ip="b",
                model_name="isolation_forest",
                score=0.5,
            ),
            ModelScore(
                event_id="evt-1",
                timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc),
                src_ip="a",
                dst_ip="b",
                model_name="autoencoder",
                score=0.5,
            ),
        ]
        assert selector._disagreement_score(agree_events) == 0.0

        # Events with very different scores → high disagreement
        disagree_events = [
            ModelScore(
                event_id="evt-2",
                timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc),
                src_ip="a",
                dst_ip="b",
                model_name="isolation_forest",
                score=0.9,
            ),
            ModelScore(
                event_id="evt-2",
                timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc),
                src_ip="a",
                dst_ip="b",
                model_name="autoencoder",
                score=0.1,
            ),
        ]
        assert selector._disagreement_score(disagree_events) > 0.5


class TestDiversitySampling:
    def test_selects_diverse_events(self, sample_events):
        selector = ActiveLearningSelector(
            strategy="diversity", batch_size=10, random_seed=42
        )
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}
        batch = selector.select_batch(sample_events, thresholds)

        assert len(batch.queries) == 10
        # Should have events from different score ranges
        scores = [q.unified_score for q in batch.queries]
        score_range = max(scores) - min(scores)
        assert score_range > 0.3  # diverse


class TestHybridStrategy:
    def test_hybrid_combines_strategies(self, sample_events):
        selector = ActiveLearningSelector(
            strategy="hybrid", batch_size=10, random_seed=42
        )
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}
        batch = selector.select_batch(sample_events, thresholds)

        assert len(batch.queries) == 10
        assert batch.strategy == "hybrid"
        # Should include a mix of uncertain and disagreement events
        selected_ids = {q.event_id for q in batch.queries}
        assert len(selected_ids) == 10  # all unique


class TestSelectFromUnlabeled:
    def test_selects_unlabeled_events(self, sample_events):
        selector = ActiveLearningSelector(batch_size=5, random_seed=42)
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}

        # Simulate unlabeled events (high score = suspicious)
        unlabeled = [e for e in sample_events if "anom" in e.event_id][:15]

        batch = selector.select_from_unlabeled(unlabeled, thresholds)

        assert len(batch.queries) == 5
        assert batch.strategy == "unlabeled"
        # Should prioritize highest-scoring events
        scores = [q.unified_score for q in batch.queries]
        assert all(s > 0.8 for s in scores)  # anomalous events have high scores

    def test_empty_unlabeled(self):
        selector = ActiveLearningSelector(batch_size=5)
        thresholds = {"isolation_forest": 0.5}
        batch = selector.select_from_unlabeled([], thresholds)
        assert len(batch.queries) == 0


class TestExcludeEvents:
    def test_exclude_already_reviewed(self, sample_events):
        selector = ActiveLearningSelector(
            strategy="uncertainty", batch_size=5, random_seed=42
        )
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}

        # First batch
        batch1 = selector.select_batch(sample_events, thresholds)
        reviewed_ids = {q.event_id for q in batch1.queries}

        # Second batch excluding reviewed
        batch2 = selector.select_batch(
            sample_events, thresholds, exclude_event_ids=reviewed_ids
        )

        batch2_ids = {q.event_id for q in batch2.queries}
        assert len(batch2_ids & reviewed_ids) == 0  # no overlap


class TestQueryContent:
    def test_query_has_model_scores(self, sample_events):
        selector = ActiveLearningSelector(strategy="hybrid", batch_size=3)
        thresholds = {"isolation_forest": 0.5, "autoencoder": 0.5, "hmm": 0.5}
        batch = selector.select_batch(sample_events, thresholds)

        for query in batch.queries:
            assert len(query.model_scores) > 0
            assert 0.0 <= query.unified_score <= 1.0
            assert query.selection_reason is not None
            assert query.uncertainty_score >= 0.0
