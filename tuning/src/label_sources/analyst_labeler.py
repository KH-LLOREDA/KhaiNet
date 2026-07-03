"""Analyst label source: converts human analyst feedback into WeakLabels.

Analyst feedback is the highest-confidence label source. When the active
learning module presents an uncertain event to the analyst, their
confirmation (True positive / False positive) becomes a ground-truth label.

These labels are critical for:
1. Calibrating thresholds with real ground truth
2. Training the weak supervisor's source weights
3. Breaking ties when other sources disagree
"""

from __future__ import annotations

from typing import Any

import structlog

from src.label_sources.base import LabelSource
from src.models import AnalystFeedback, WeakLabel

log = structlog.get_logger()


class AnalystLabeler(LabelSource):
    """Convert analyst feedback into WeakLabels.

    Analyst labels have maximum confidence (1.0) because they come from
    human judgment — the ultimate ground truth.

    Args:
        weight: Weight in the weak supervisor (highest by default).
        min_confidence: Minimum confidence to emit a label.
    """

    def __init__(
        self,
        weight: float = 2.0,
        min_confidence: float = 0.0,
    ) -> None:
        super().__init__(name="analyst", weight=weight, min_confidence=min_confidence)

    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert AnalystFeedback objects into WeakLabels.

        Args:
            raw_data: List of AnalystFeedback objects.

        Returns:
            List of WeakLabel objects with confidence=1.0 (human ground truth).
        """
        if not isinstance(raw_data, list):
            return []

        feedbacks = [f for f in raw_data if isinstance(f, AnalystFeedback)]
        labels: list[WeakLabel] = []

        for feedback in feedbacks:
            labels.append(
                WeakLabel(
                    event_id=feedback.event_id,
                    timestamp=feedback.timestamp,
                    src_ip=feedback.src_ip,
                    dst_ip=feedback.dst_ip,
                    source=self.name,
                    label=feedback.label,  # True=anomaly, False=normal
                    confidence=1.0,  # human ground truth = maximum confidence
                    event_type="analyst_confirmed",
                    mitre_attack_id=feedback.mitre_attack_id,
                )
            )

        log.info(
            "analyst_labels_generated",
            n_feedbacks=len(feedbacks),
            n_labels=len(labels),
            n_positive=sum(1 for l in labels if l.label is True),
            n_negative=sum(1 for l in labels if l.label is False),
        )
        return labels
