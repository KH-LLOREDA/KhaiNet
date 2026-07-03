"""Active learning: select the most informative events for analyst review.

The active learning module identifies events where the system is most
uncertain and presents them to the analyst for confirmation. This is
critical for the auto-labeling pipeline because:

1. Events with no source votes (unlabeled) need human input
2. Events near the decision threshold are uncertain and high-value
3. Events where models disagree are likely to be edge cases
4. Diverse selection ensures coverage of different attack types

Strategies:
- **uncertainty**: Select events with unified score closest to the threshold
- **disagreement**: Select events where the 3 models disagree most
- **diversity**: Select events covering different score ranges / event types
- **hybrid**: Combine all three strategies with configurable weights

The analyst's feedback (AnalystFeedback) is fed back into the weak supervisor
as the highest-confidence source, improving future labeling.
"""

from __future__ import annotations

import random

import numpy as np
import structlog

from src.models import (
    ActiveLearningBatch,
    ActiveLearningQuery,
    ModelScore,
)

log = structlog.get_logger()


class ActiveLearningSelector:
    """Select the most informative events for analyst review.

    Args:
        strategy: Selection strategy (uncertainty, disagreement, diversity, hybrid).
        batch_size: Number of events to select per batch.
        uncertainty_weight: Weight for uncertainty in hybrid mode (0-1).
        disagreement_weight: Weight for disagreement in hybrid mode (0-1).
        diversity_weight: Weight for diversity in hybrid mode (0-1).
        random_seed: Random seed for reproducibility.
    """

    def __init__(
        self,
        strategy: str = "hybrid",
        batch_size: int = 20,
        uncertainty_weight: float = 0.5,
        disagreement_weight: float = 0.3,
        diversity_weight: float = 0.2,
        random_seed: int = 42,
    ) -> None:
        self.strategy = strategy
        self.batch_size = batch_size
        self.uncertainty_weight = uncertainty_weight
        self.disagreement_weight = disagreement_weight
        self.diversity_weight = diversity_weight
        self._rng = random.Random(random_seed)

    # ------------------------------------------------------------------
    # Uncertainty sampling
    # ------------------------------------------------------------------

    def _uncertainty_score(
        self,
        unified_score: float,
        threshold: float,
    ) -> float:
        """Calculate uncertainty score: 1.0 at threshold, 0.0 far from it.

        Uses a Gaussian-like falloff: uncertainty = exp(-(score - threshold)² / (2σ²))
        with σ = 0.15 (so uncertainty drops to ~0.5 at ±0.15 from threshold).

        Args:
            unified_score: The event's unified anomaly score (0-1).
            threshold: The current decision threshold.

        Returns:
            Uncertainty score in [0, 1].
        """
        sigma = 0.15
        diff = unified_score - threshold
        return float(np.exp(-(diff**2) / (2 * sigma**2)))

    def _select_uncertainty(
        self,
        events: list[ModelScore],
        thresholds: dict[str, float],
        unified_scores: dict[str, float] | None = None,
    ) -> list[tuple[str, float]]:
        """Select events by uncertainty (closest to threshold).

        Args:
            events: Model events.
            thresholds: Per-model thresholds.
            unified_scores: Optional pre-computed unified scores per event_id.

        Returns:
            List of (event_id, uncertainty_score) sorted by uncertainty descending.
        """
        results: list[tuple[str, float]] = []

        # Group events by event_id to get all model scores per event
        events_by_id: dict[str, list[ModelScore]] = {}
        for evt in events:
            events_by_id.setdefault(evt.event_id, []).append(evt)

        for event_id, model_events in events_by_id.items():
            if unified_scores and event_id in unified_scores:
                score = unified_scores[event_id]
            else:
                # Average score across models as proxy for unified score
                score = float(np.mean([e.score for e in model_events]))

            # Use average threshold across models
            avg_threshold = (
                float(np.mean(list(thresholds.values()))) if thresholds else 0.5
            )
            uncertainty = self._uncertainty_score(score, avg_threshold)
            results.append((event_id, uncertainty))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Disagreement sampling
    # ------------------------------------------------------------------

    def _disagreement_score(self, model_events: list[ModelScore]) -> float:
        """Calculate disagreement score: how much the models disagree.

        Uses the standard deviation of model scores normalized to [0, 1].
        High std = high disagreement = high uncertainty.

        Args:
            model_events: Model scores for a single event.

        Returns:
            Disagreement score in [0, 1].
        """
        if len(model_events) < 2:
            return 0.0
        scores = [e.score for e in model_events]
        std = float(np.std(scores))
        # Normalize: max possible std for [0,1] values is ~0.5
        return min(std / 0.5, 1.0)

    def _select_disagreement(
        self,
        events: list[ModelScore],
    ) -> list[tuple[str, float]]:
        """Select events by model disagreement.

        Args:
            events: Model events.

        Returns:
            List of (event_id, disagreement_score) sorted by disagreement descending.
        """
        events_by_id: dict[str, list[ModelScore]] = {}
        for evt in events:
            events_by_id.setdefault(evt.event_id, []).append(evt)

        results: list[tuple[str, float]] = []
        for event_id, model_events in events_by_id.items():
            disagreement = self._disagreement_score(model_events)
            results.append((event_id, disagreement))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Diversity sampling
    # ------------------------------------------------------------------

    def _select_diversity(
        self,
        events: list[ModelScore],
    ) -> list[tuple[str, float]]:
        """Select events by diversity (cover different score ranges).

        Divides the score range [0, 1] into bins and selects events from
        different bins to ensure coverage.

        Args:
            events: Model events.

        Returns:
            List of (event_id, diversity_score) where diversity_score is
            the bin rarity (higher = more diverse).
        """
        events_by_id: dict[str, list[ModelScore]] = {}
        for evt in events:
            events_by_id.setdefault(evt.event_id, []).append(evt)

        # Compute average score per event
        event_scores: list[tuple[str, float]] = []
        for event_id, model_events in events_by_id.items():
            avg_score = float(np.mean([e.score for e in model_events]))
            event_scores.append((event_id, avg_score))

        # Bin into 10 bins
        n_bins = 10
        bin_counts: dict[int, int] = {i: 0 for i in range(n_bins)}
        event_bins: dict[str, int] = {}

        for event_id, avg_score in event_scores:
            bin_idx = min(int(avg_score * n_bins), n_bins - 1)
            event_bins[event_id] = bin_idx
            bin_counts[bin_idx] += 1

        # Diversity score: inverse of bin frequency (rarer bins = higher diversity)
        total = len(event_scores) or 1
        results: list[tuple[str, float]] = []
        for event_id, _ in event_scores:
            bin_idx = event_bins[event_id]
            rarity = 1.0 - (bin_counts[bin_idx] / total)
            results.append((event_id, rarity))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Hybrid selection
    # ------------------------------------------------------------------

    def _select_hybrid(
        self,
        events: list[ModelScore],
        thresholds: dict[str, float],
        unified_scores: dict[str, float] | None = None,
    ) -> list[tuple[str, float]]:
        """Combine uncertainty, disagreement, and diversity scores.

        Args:
            events: Model events.
            thresholds: Per-model thresholds.
            unified_scores: Optional pre-computed unified scores.

        Returns:
            List of (event_id, combined_score) sorted by score descending.
        """
        uncertainty = dict(self._select_uncertainty(events, thresholds, unified_scores))
        disagreement = dict(self._select_disagreement(events))
        diversity = dict(self._select_diversity(events))

        all_ids = set(uncertainty) | set(disagreement) | set(diversity)
        results: list[tuple[str, float]] = []

        for event_id in all_ids:
            u = uncertainty.get(event_id, 0.0)
            d = disagreement.get(event_id, 0.0)
            v = diversity.get(event_id, 0.0)
            combined = (
                self.uncertainty_weight * u
                + self.disagreement_weight * d
                + self.diversity_weight * v
            )
            results.append((event_id, combined))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def select_batch(
        self,
        events: list[ModelScore],
        thresholds: dict[str, float],
        unified_scores: dict[str, float] | None = None,
        exclude_event_ids: set[str] | None = None,
    ) -> ActiveLearningBatch:
        """Select a batch of events for analyst review.

        Args:
            events: All model events.
            thresholds: Per-model decision thresholds.
            unified_scores: Optional pre-computed unified scores per event_id.
            exclude_event_ids: Event IDs to exclude (already reviewed).

        Returns:
            ActiveLearningBatch with the selected queries.
        """
        exclude = exclude_event_ids or set()
        candidate_events = [e for e in events if e.event_id not in exclude]

        if not candidate_events:
            log.warning("no_candidates_for_active_learning")
            return ActiveLearningBatch(
                queries=[],
                strategy=self.strategy,
                batch_size=0,
                model_thresholds=thresholds,
            )

        # Select by strategy
        if self.strategy == "uncertainty":
            ranked = self._select_uncertainty(
                candidate_events, thresholds, unified_scores
            )
        elif self.strategy == "disagreement":
            ranked = self._select_disagreement(candidate_events)
        elif self.strategy == "diversity":
            ranked = self._select_diversity(candidate_events)
        else:  # hybrid
            ranked = self._select_hybrid(candidate_events, thresholds, unified_scores)

        # Take top N
        selected = ranked[: self.batch_size]

        # Build queries
        events_by_id: dict[str, list[ModelScore]] = {}
        for evt in candidate_events:
            events_by_id.setdefault(evt.event_id, []).append(evt)

        queries: list[ActiveLearningQuery] = []
        for event_id, score in selected:
            model_events = events_by_id.get(event_id, [])
            if not model_events:
                continue

            first = model_events[0]
            model_scores = {e.model_name: e.score for e in model_events}
            unified = (
                unified_scores.get(event_id)
                if unified_scores
                else float(np.mean([e.score for e in model_events]))
            )
            avg_threshold = (
                float(np.mean(list(thresholds.values()))) if thresholds else 0.5
            )

            # Suggested label based on current threshold
            suggested = unified >= avg_threshold if unified is not None else None

            queries.append(
                ActiveLearningQuery(
                    event_id=event_id,
                    timestamp=first.timestamp,
                    src_ip=first.src_ip,
                    dst_ip=first.dst_ip,
                    model_scores=model_scores,
                    unified_score=unified or 0.0,
                    current_threshold=avg_threshold,
                    selection_reason=self.strategy,
                    uncertainty_score=score,
                    suggested_label=suggested,
                    context={
                        "n_models": len(model_events),
                        "model_names": list(model_scores.keys()),
                    },
                )
            )

        batch = ActiveLearningBatch(
            queries=queries,
            strategy=self.strategy,
            batch_size=len(queries),
            model_thresholds=thresholds,
        )

        log.info(
            "active_learning_batch_selected",
            strategy=self.strategy,
            batch_size=len(queries),
            n_candidates=len(candidate_events),
            avg_uncertainty=float(np.mean([q.uncertainty_score for q in queries]))
            if queries
            else 0.0,
        )
        return batch

    def select_from_unlabeled(
        self,
        unlabeled_events: list[ModelScore],
        thresholds: dict[str, float],
        unified_scores: dict[str, float] | None = None,
    ) -> ActiveLearningBatch:
        """Select events that received no label from any source.

        These are the highest-priority events for active learning because
        the system has no information about them.

        Args:
            unlabeled_events: Events without any consensus label.
            thresholds: Per-model thresholds.
            unified_scores: Optional unified scores.

        Returns:
            ActiveLearningBatch with queries for the unlabeled events.
        """
        if not unlabeled_events:
            return ActiveLearningBatch(
                queries=[],
                strategy="unlabeled",
                batch_size=0,
                model_thresholds=thresholds,
            )

        # For unlabeled events, prioritize by score (higher score = more
        # likely to be an anomaly that we're missing)
        events_by_id: dict[str, list[ModelScore]] = {}
        for evt in unlabeled_events:
            events_by_id.setdefault(evt.event_id, []).append(evt)

        # Sort by unified score descending (most suspicious first)
        scored: list[tuple[str, float]] = []
        for event_id, model_events in events_by_id.items():
            if unified_scores and event_id in unified_scores:
                score = unified_scores[event_id]
            else:
                score = float(np.mean([e.score for e in model_events]))
            scored.append((event_id, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        selected = scored[: self.batch_size]

        queries: list[ActiveLearningQuery] = []
        for event_id, score in selected:
            model_events = events_by_id.get(event_id, [])
            if not model_events:
                continue

            first = model_events[0]
            model_scores = {e.model_name: e.score for e in model_events}
            avg_threshold = (
                float(np.mean(list(thresholds.values()))) if thresholds else 0.5
            )

            queries.append(
                ActiveLearningQuery(
                    event_id=event_id,
                    timestamp=first.timestamp,
                    src_ip=first.src_ip,
                    dst_ip=first.dst_ip,
                    model_scores=model_scores,
                    unified_score=score,
                    current_threshold=avg_threshold,
                    selection_reason="unlabeled",
                    uncertainty_score=1.0 - abs(score - avg_threshold),
                    suggested_label=score >= avg_threshold,
                    context={
                        "n_models": len(model_events),
                        "model_names": list(model_scores.keys()),
                        "reason": "No source labeled this event",
                    },
                )
            )

        batch = ActiveLearningBatch(
            queries=queries,
            strategy="unlabeled",
            batch_size=len(queries),
            model_thresholds=thresholds,
        )

        log.info(
            "unlabeled_batch_selected",
            batch_size=len(queries),
            n_unlabeled=len(unlabeled_events),
        )
        return batch
