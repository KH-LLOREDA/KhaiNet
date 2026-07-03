"""Brain label source: converts Brain correlations into WeakLabels.

The Brain component correlates multiple anomaly events across the 3 ML
models (Isolation Forest, Autoencoder, HMM) and maps them to MITRE ATT&CK
tactics/techniques. Brain's correlations are medium-confidence positive
labels — Brain identifies patterns, but doesn't have ground truth.

Brain labels are "weak" because:
1. Brain operates on pre-filtered ML anomalies (could be false positives)
2. Brain's confidence depends on the number and quality of contributing events
3. Brain's MITRE mapping is heuristic, not definitive

Confidence: uses Brain's own confidence value, scaled by a factor.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.label_sources.base import LabelSource
from src.models import BrainCorrelation, WeakLabel

log = structlog.get_logger()


class BrainLabeler(LabelSource):
    """Convert Brain correlations into WeakLabels.

    Args:
        weight: Weight in the weak supervisor (lower than signature sources).
        min_confidence: Minimum confidence to emit a label.
        confidence_scale: Scale factor for Brain's confidence (default 0.8).
            Brain's confidence is inherently weaker than signature-based
            sources, so we scale it down.
    """

    def __init__(
        self,
        weight: float = 0.7,
        min_confidence: float = 0.3,
        confidence_scale: float = 0.8,
    ) -> None:
        super().__init__(name="brain", weight=weight, min_confidence=min_confidence)
        self.confidence_scale = confidence_scale

    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert BrainCorrelation objects into WeakLabels.

        Args:
            raw_data: List of BrainCorrelation objects.

        Returns:
            List of WeakLabel objects with label=True and scaled confidence.
        """
        if not isinstance(raw_data, list):
            return []

        correlations = [c for c in raw_data if isinstance(c, BrainCorrelation)]
        labels: list[WeakLabel] = []

        for corr in correlations:
            # Scale Brain's confidence down (it's a weak signal)
            confidence = corr.confidence * self.confidence_scale
            if confidence < self.min_confidence:
                continue

            # Map MITRE tactic to event type
            event_type = _mitre_tactic_to_event_type(corr.mitre_tactic)

            labels.append(
                WeakLabel(
                    event_id="",
                    timestamp=corr.timestamp,
                    src_ip=corr.src_ip,
                    dst_ip=corr.dst_ip,
                    source=self.name,
                    label=True,  # Brain correlation = likely anomaly
                    confidence=confidence,
                    event_type=event_type,
                    mitre_attack_id=corr.mitre_attack_id,
                )
            )

        log.info(
            "brain_labels_generated",
            n_correlations=len(correlations),
            n_labels=len(labels),
            confidence_scale=self.confidence_scale,
        )
        return labels


def _mitre_tactic_to_event_type(tactic: str) -> str:
    """Map MITRE ATT&CK tactic to KhaiNet event type."""
    tactic_lower = tactic.lower()
    if "exfiltration" in tactic_lower:
        return "exfiltration"
    if "command and control" in tactic_lower or "c2" in tactic_lower:
        return "c2_beaconing"
    if "lateral" in tactic_lower:
        return "lateral_movement"
    if "discovery" in tactic_lower or "reconnaissance" in tactic_lower:
        return "scan"
    if "credential" in tactic_lower:
        return "credential_theft"
    return "anomaly"
