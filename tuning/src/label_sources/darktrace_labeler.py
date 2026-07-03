"""Darktrace label source: adapts the existing LabelImporter as a LabelSource.

When Darktrace is available (not in isolated environments), its alerts
serve as high-confidence positive labels — the original ground truth source.
This adapter wraps the existing LabelImporter to conform to the LabelSource
interface, making Darktrace one more source in the weak supervision pipeline.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.label_importer import LabelImporter
from src.label_sources.base import LabelSource
from src.models import DarktraceAlert, WeakLabel

log = structlog.get_logger()


class DarktraceLabeler(LabelSource):
    """Convert Darktrace alerts into WeakLabels via the existing LabelImporter.

    This is an optional source — when Darktrace is available, it provides
    high-quality labels. When it's not (isolated environments), the other
    sources (Suricata, Wazuh, MISP, Brain, Analyst) take over.

    Args:
        weight: Weight in the weak supervisor (high, since DT is the
            original ground truth).
        min_confidence: Minimum confidence to emit a label.
        min_severity: Minimum Darktrace severity to include.
        deduplicate: Whether to deduplicate alerts.
    """

    def __init__(
        self,
        weight: float = 1.5,
        min_confidence: float = 0.5,
        min_severity: str = "low",
        deduplicate: bool = True,
    ) -> None:
        super().__init__(name="darktrace", weight=weight, min_confidence=min_confidence)
        self._importer = LabelImporter(
            min_severity=min_severity,
            deduplicate=deduplicate,
        )

    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert DarktraceAlert objects into WeakLabels.

        Uses the existing LabelImporter to convert alerts to SupervisedLabels,
        then wraps them as WeakLabels.

        Args:
            raw_data: List of DarktraceAlert objects.

        Returns:
            List of WeakLabel objects with label=True and DT-derived confidence.
        """
        if not isinstance(raw_data, list):
            return []

        alerts = [a for a in raw_data if isinstance(a, DarktraceAlert)]
        if not alerts:
            return []

        # Use existing LabelImporter for the conversion logic
        supervised = self._importer.import_labels(alerts)

        labels: list[WeakLabel] = []
        for sl in supervised:
            if sl.confidence < self.min_confidence:
                continue
            labels.append(
                WeakLabel(
                    event_id=sl.event_id,
                    timestamp=sl.timestamp,
                    src_ip=sl.src_ip,
                    dst_ip=sl.dst_ip,
                    source=self.name,
                    label=sl.label,
                    confidence=sl.confidence,
                    event_type=sl.event_type,
                )
            )

        log.info(
            "darktrace_labels_generated",
            n_alerts=len(alerts),
            n_labels=len(labels),
        )
        return labels
