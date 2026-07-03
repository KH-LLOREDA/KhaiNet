"""Wazuh label source: converts Wazuh HIDS alerts into WeakLabels.

Wazuh is a Host Intrusion Detection System (HIDS) that monitors endpoints
for file integrity changes, rootkit detection, log analysis, vulnerability
detection, and compliance checking.

Wazuh alerts with rule_level >= 7 are high severity and indicate likely
security incidents. These are medium-to-high confidence positive labels.

Confidence mapping (Wazuh rule_level → confidence):
- Level 12-15: 0.95 (critical)
- Level 9-11:  0.85 (high)
- Level 6-8:   0.70 (medium)
- Level 3-5:   0.50 (low)
- Level 0-2:   0.30 (very low — usually informational)
"""

from __future__ import annotations

from typing import Any

import structlog

from src.label_sources.base import LabelSource
from src.models import WazuhAlert, WeakLabel

log = structlog.get_logger()


def _wazuh_confidence(rule_level: int) -> float:
    """Map Wazuh rule level to confidence."""
    if rule_level >= 12:
        return 0.95
    if rule_level >= 9:
        return 0.85
    if rule_level >= 6:
        return 0.70
    if rule_level >= 3:
        return 0.50
    return 0.30


# Wazuh rule groups → event type mapping
WAZUH_GROUP_TO_EVENT_TYPE: dict[str, str] = {
    "syscheck": "file_integrity",
    "rootcheck": "rootkit",
    "auth": "auth_anomaly",
    "web": "web_attack",
    "malware": "malware",
    "vulnerability-detector": "vulnerability",
    "sql_injection": "sql_injection",
    "xss": "xss",
}


class WazuhLabeler(LabelSource):
    """Convert Wazuh HIDS alerts into WeakLabels.

    Args:
        weight: Weight in the weak supervisor.
        min_confidence: Minimum confidence to emit a label.
        min_rule_level: Minimum Wazuh rule level to include (default 6).
    """

    def __init__(
        self,
        weight: float = 1.0,
        min_confidence: float = 0.5,
        min_rule_level: int = 6,
    ) -> None:
        super().__init__(name="wazuh", weight=weight, min_confidence=min_confidence)
        self.min_rule_level = min_rule_level

    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert WazuhAlert objects into WeakLabels.

        Args:
            raw_data: List of WazuhAlert objects.

        Returns:
            List of WeakLabel objects. Labels with IPs are positive (anomaly).
            Labels without IPs (host-only events) are included with lower
            confidence and will only match events from the same host.
        """
        if not isinstance(raw_data, list):
            return []

        alerts = [a for a in raw_data if isinstance(a, WazuhAlert)]
        labels: list[WeakLabel] = []

        for alert in alerts:
            if alert.rule_level < self.min_rule_level:
                continue

            confidence = _wazuh_confidence(alert.rule_level)
            if confidence < self.min_confidence:
                continue

            # Determine event type from rule groups
            event_type = "anomaly"
            for group in alert.rule_groups:
                if group in WAZUH_GROUP_TO_EVENT_TYPE:
                    event_type = WAZUH_GROUP_TO_EVENT_TYPE[group]
                    break

            # Wazuh alerts with IPs → positive label (anomaly detected)
            # Wazuh alerts without IPs → still positive but lower confidence
            # (host-based event, may not correlate with network event)
            label = True
            if not alert.src_ip and not alert.dst_ip:
                # Host-only event: lower confidence, use agent_id as src_ip
                confidence *= 0.7

            # Use agent_id as a fallback IP if no network IPs
            src_ip = alert.src_ip or f"agent:{alert.agent_id}"
            dst_ip = alert.dst_ip or ""

            labels.append(
                WeakLabel(
                    event_id="",
                    timestamp=alert.timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    source=self.name,
                    label=label,
                    confidence=confidence,
                    event_type=event_type,
                )
            )

        log.info(
            "wazuh_labels_generated",
            n_alerts=len(alerts),
            n_labels=len(labels),
            min_rule_level=self.min_rule_level,
        )
        return labels
