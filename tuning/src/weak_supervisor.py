"""Weak supervisor: combine multiple label sources into consensus labels.

Inspired by Snorkel's weak supervision approach. Multiple "labelling
functions" (label sources) each vote on whether an event is an anomaly.
The supervisor combines these votes, weighted by each source's confidence
and reliability, to produce a final ConsensusLabel.

Algorithm:
    For each event with one or more WeakLabels:
    1. Collect all votes (label + confidence + source weight)
    2. Compute weighted vote score:
       score = Σ(source_weight × confidence × vote) / Σ(source_weight × confidence)
       where vote = +1 for True, -1 for False, 0 for abstain
    3. Final label = score > 0 → True, score < 0 → False, score == 0 → abstain
    4. Final confidence = |score| (how strong the consensus is)

    Events with no votes from any source get label=False (default normal)
    with confidence=0.0, and are candidates for active learning.

Analyst labels always override other sources (weight=2.0, confidence=1.0).
If an analyst has labeled an event, their label is final.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog

from src.label_sources.base import LabelSource
from src.models import ConsensusLabel, ModelScore, WeakLabel

log = structlog.get_logger()


class WeakSupervisor:
    """Combine multiple label sources into consensus labels via weighted voting.

    Args:
        sources: List of LabelSource instances to use.
        decision_threshold: Score above which the label is True (default 0.0,
            meaning any positive weighted vote wins). Set higher for more
            conservative labeling.
        abstain_threshold: Below this absolute score, the supervisor abstains
            (returns None label). Events with abstained labels are candidates
            for active learning.
        analyst_override: If True, analyst labels always override other votes.
    """

    def __init__(
        self,
        sources: list[LabelSource],
        decision_threshold: float = 0.0,
        abstain_threshold: float = 0.0,
        analyst_override: bool = True,
    ) -> None:
        self.sources = sources
        self.decision_threshold = decision_threshold
        self.abstain_threshold = abstain_threshold
        self.analyst_override = analyst_override
        self._source_by_name = {s.name: s for s in sources}

    def combine_labels(
        self,
        weak_labels: list[WeakLabel],
    ) -> list[ConsensusLabel]:
        """Combine multiple WeakLabels into ConsensusLabels.

        Groups WeakLabels by event_id and produces one ConsensusLabel per event.

        Args:
            weak_labels: All WeakLabels from all sources, for all events.

        Returns:
            List of ConsensusLabel, one per event that has at least one vote.
        """
        # Group labels by event_id
        labels_by_event: dict[str, list[WeakLabel]] = defaultdict(list)
        for wl in weak_labels:
            if wl.event_id and wl.label is not None:
                labels_by_event[wl.event_id].append(wl)

        consensus_labels: list[ConsensusLabel] = []

        for event_id, votes in labels_by_event.items():
            consensus = self._combine_votes(event_id, votes)
            if consensus is not None:
                consensus_labels.append(consensus)

        log.info(
            "weak_supervision_complete",
            n_events_with_votes=len(labels_by_event),
            n_consensus_labels=len(consensus_labels),
            n_positive=sum(1 for c in consensus_labels if c.label),
            n_negative=sum(1 for c in consensus_labels if not c.label),
        )
        return consensus_labels

    def _combine_votes(
        self,
        event_id: str,
        votes: list[WeakLabel],
    ) -> ConsensusLabel | None:
        """Combine votes for a single event into a ConsensusLabel.

        Args:
            event_id: The event ID.
            votes: List of WeakLabels for this event.

        Returns:
            ConsensusLabel, or None if all sources abstained.
        """
        # Check for analyst override
        if self.analyst_override:
            analyst_votes = [v for v in votes if v.source == "analyst"]
            if analyst_votes:
                # Use the most recent analyst vote
                analyst_vote = max(analyst_votes, key=lambda v: v.ts_epoch)
                return self._make_consensus(event_id, votes, analyst_vote.label, 1.0)

        # Weighted voting
        total_weight = 0.0
        weighted_sum = 0.0
        vote_breakdown: dict[str, Any] = {}
        votes_positive = 0
        votes_negative = 0
        votes_abstain = 0

        for vote in votes:
            source_weight = self._get_source_weight(vote.source)
            effective_weight = source_weight * vote.confidence

            if vote.label is True:
                weighted_sum += effective_weight
                votes_positive += 1
                vote_breakdown[vote.source] = {
                    "label": True,
                    "confidence": vote.confidence,
                    "weight": source_weight,
                }
            elif vote.label is False:
                weighted_sum -= effective_weight
                votes_negative += 1
                vote_breakdown[vote.source] = {
                    "label": False,
                    "confidence": vote.confidence,
                    "weight": source_weight,
                }
            else:
                votes_abstain += 1
                vote_breakdown[vote.source] = {
                    "label": None,
                    "confidence": vote.confidence,
                    "weight": source_weight,
                }

            total_weight += effective_weight

        # Compute final score
        if total_weight == 0:
            # All sources abstained
            return None

        score = weighted_sum / total_weight  # in [-1.0, 1.0]

        # Check abstain threshold
        if abs(score) < self.abstain_threshold:
            return None

        # Decision
        label = score > self.decision_threshold
        confidence = abs(score)

        return self._make_consensus(
            event_id,
            votes,
            label,
            confidence,
            vote_breakdown=vote_breakdown,
            votes_positive=votes_positive,
            votes_negative=votes_negative,
            votes_abstain=votes_abstain,
        )

    def _make_consensus(
        self,
        event_id: str,
        votes: list[WeakLabel],
        label: bool,
        confidence: float,
        vote_breakdown: dict[str, Any] | None = None,
        votes_positive: int = 0,
        votes_negative: int = 0,
        votes_abstain: int = 0,
    ) -> ConsensusLabel:
        """Create a ConsensusLabel from votes and decision."""
        # Use the first vote's timestamp and IPs (all votes should be for the same event)
        first = votes[0]
        contributing_sources = list({v.source for v in votes})

        # Extract MITRE ATT&CK ID if any source provided one
        mitre_id = None
        event_type = None
        for v in votes:
            if v.mitre_attack_id and not mitre_id:
                mitre_id = v.mitre_attack_id
            if v.event_type and not event_type:
                event_type = v.event_type

        return ConsensusLabel(
            event_id=event_id,
            timestamp=first.timestamp,
            src_ip=first.src_ip,
            dst_ip=first.dst_ip,
            label=label,
            confidence=confidence,
            source="weak_supervision",
            contributing_sources=contributing_sources,
            vote_breakdown=vote_breakdown or {},
            votes_positive=votes_positive,
            votes_negative=votes_negative,
            votes_abstain=votes_abstain,
            event_type=event_type,
            mitre_attack_id=mitre_id,
        )

    def _get_source_weight(self, source_name: str) -> float:
        """Get the weight for a source by name."""
        source = self._source_by_name.get(source_name)
        return source.weight if source else 1.0

    def label_events(
        self,
        events: list[ModelScore],
        source_data: dict[str, Any],
        window_seconds: float = 60.0,
    ) -> list[ConsensusLabel]:
        """Full pipeline: generate labels from all sources, match, and combine.

        This is the main entry point for the auto-labeling pipeline:
        1. Each source generates WeakLabels from its raw data
        2. Labels are matched to events by IP + temporal proximity
        3. Matched labels are combined into ConsensusLabels

        Args:
            events: Model events to label.
            source_data: Dict mapping source name → raw data for that source.
                e.g. {"suricata": [SuricataAlert, ...], "wazuh": [WazuhAlert, ...]}
            window_seconds: Temporal matching window.

        Returns:
            List of ConsensusLabel, one per event that received at least one vote.
        """
        all_weak_labels: list[WeakLabel] = []

        for source in self.sources:
            raw = source_data.get(source.name)
            if raw is None:
                continue

            # Generate labels from this source
            labels = source.generate_labels(raw)

            # Match labels to events
            matched = source.match_to_events(labels, events, window_seconds)
            all_weak_labels.extend(matched)

        # Combine all matched labels into consensus labels
        consensus = self.combine_labels(all_weak_labels)

        log.info(
            "auto_labeling_pipeline_complete",
            n_events=len(events),
            n_sources=len(self.sources),
            n_weak_labels=len(all_weak_labels),
            n_consensus_labels=len(consensus),
        )
        return consensus

    def get_unlabeled_events(
        self,
        events: list[ModelScore],
        consensus_labels: list[ConsensusLabel],
    ) -> list[ModelScore]:
        """Return events that received no consensus label.

        These are candidates for active learning — the system couldn't
        label them from any source, so they need human review.

        Args:
            events: All model events.
            consensus_labels: Consensus labels produced by combine_labels.

        Returns:
            List of events without any label.
        """
        labeled_ids = {cl.event_id for cl in consensus_labels}
        return [e for e in events if e.event_id not in labeled_ids]

    def get_source_statistics(
        self,
        weak_labels: list[WeakLabel],
    ) -> dict[str, dict[str, Any]]:
        """Compute statistics per source for monitoring and weight tuning.

        Args:
            weak_labels: All weak labels from all sources.

        Returns:
            Dict mapping source name → statistics (count, avg confidence,
            positive/negative/abstain counts).
        """
        stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "count": 0,
                "positive": 0,
                "negative": 0,
                "abstain": 0,
                "avg_confidence": 0.0,
            }
        )

        for wl in weak_labels:
            s = stats[wl.source]
            s["count"] += 1
            if wl.label is True:
                s["positive"] += 1
            elif wl.label is False:
                s["negative"] += 1
            else:
                s["abstain"] += 1
            s["avg_confidence"] += wl.confidence

        for s in stats.values():
            if s["count"] > 0:
                s["avg_confidence"] /= s["count"]

        return dict(stats)
