"""MISP label source: converts threat intelligence IOCs into WeakLabels.

MISP (Malware Information Sharing Platform) provides Indicators of
Compromise (IOCs): malicious IPs, domains, URLs, file hashes, etc.
When a network event matches a MISP IOC, it's a high-confidence positive
label because the IOC comes from curated threat intelligence feeds.

Confidence mapping (MISP threat_level → confidence):
- Level 1 (high):     0.95
- Level 2 (medium):   0.85
- Level 3 (low):      0.70
- Level 4 (undefined): 0.60
"""

from __future__ import annotations

from typing import Any

import structlog

from src.label_sources.base import LabelSource
from src.models import MISPEvent, WeakLabel

log = structlog.get_logger()

MISP_THREAT_LEVEL_CONFIDENCE: dict[int, float] = {
    1: 0.95,  # high
    2: 0.85,  # medium
    3: 0.70,  # low
    4: 0.60,  # undefined
}


class MISPLabeler(LabelSource):
    """Convert MISP threat intelligence events into WeakLabels.

    Args:
        weight: Weight in the weak supervisor.
        min_confidence: Minimum confidence to emit a label.
    """

    def __init__(
        self,
        weight: float = 1.3,
        min_confidence: float = 0.5,
    ) -> None:
        super().__init__(name="misp", weight=weight, min_confidence=min_confidence)

    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert MISPEvent objects into WeakLabels.

        Args:
            raw_data: List of MISPEvent objects.

        Returns:
            List of WeakLabel objects with label=True (IOC match = anomaly).
        """
        if not isinstance(raw_data, list):
            return []

        events = [e for e in raw_data if isinstance(e, MISPEvent)]
        labels: list[WeakLabel] = []

        for event in events:
            confidence = MISP_THREAT_LEVEL_CONFIDENCE.get(event.threat_level, 0.60)
            if confidence < self.min_confidence:
                continue

            # Extract event type from IOC type or tags
            event_type = "threat_intel_match"
            if "c2" in event.tags or "botnet" in event.tags:
                event_type = "c2_beaconing"
            elif "exfiltration" in event.tags:
                event_type = "exfiltration"
            elif "scan" in event.tags or "recon" in event.tags:
                event_type = "scan"

            labels.append(
                WeakLabel(
                    event_id="",
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    source=self.name,
                    label=True,  # IOC match = confirmed malicious
                    confidence=confidence,
                    event_type=event_type,
                    mitre_attack_id=event.mitre_attack_id,
                )
            )

        log.info(
            "misp_labels_generated",
            n_events=len(events),
            n_labels=len(labels),
        )
        return labels
