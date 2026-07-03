"""Suricata label source: converts EVE JSON alerts into WeakLabels.

Suricata is a signature-based IDS/IPS. When its rules (ET rules, custom)
match network traffic, it generates alerts in the EVE JSON format.
These are high-confidence positive labels because signature matches
indicate known attack patterns.

Confidence mapping (Suricata severity → confidence):
- Severity 1 (high)   → 0.95
- Severity 2 (medium) → 0.80
- Severity 3 (low)    → 0.60
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from src.label_sources.base import LabelSource
from src.models import SuricataAlert, WeakLabel

log = structlog.get_logger()

# Suricata severity → confidence mapping
SURICATA_SEVERITY_CONFIDENCE: dict[int, float] = {
    1: 0.95,  # high
    2: 0.80,  # medium
    3: 0.60,  # low
}

# Suricata category → event type mapping
SURICATA_CATEGORY_TO_EVENT_TYPE: dict[str, str] = {
    "Trojan Activity": "c2_beaconing",
    "Attempted Administrator Privilege Gain": "lateral_movement",
    "Attempted User Privilege Gain": "lateral_movement",
    "Data Exfiltration": "exfiltration",
    "DNS Tunneling": "dns_tunneling",
    "Network Scan": "scan",
    "Malware Command and Control Activity Detected": "c2_beaconing",
}


class SuricataLabeler(LabelSource):
    """Convert Suricata EVE JSON alerts into WeakLabels.

    Args:
        weight: Weight in the weak supervisor.
        min_confidence: Minimum confidence to emit a label.
    """

    def __init__(
        self,
        weight: float = 1.2,
        min_confidence: float = 0.5,
    ) -> None:
        super().__init__(name="suricata", weight=weight, min_confidence=min_confidence)

    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert SuricataAlert objects (or EVE JSON dicts) into WeakLabels.

        Args:
            raw_data: Either a list of SuricataAlert objects, a list of
                raw EVE JSON dicts, or a path to an EVE JSON file.

        Returns:
            List of WeakLabel objects with label=True (signature match = anomaly).
        """
        alerts = self._normalize_input(raw_data)
        labels: list[WeakLabel] = []

        for alert in alerts:
            confidence = SURICATA_SEVERITY_CONFIDENCE.get(alert.alert_severity, 0.5)
            if confidence < self.min_confidence:
                continue

            event_type = SURICATA_CATEGORY_TO_EVENT_TYPE.get(
                alert.alert_category, "anomaly"
            )

            labels.append(
                WeakLabel(
                    event_id="",  # will be set by match_to_events
                    timestamp=alert.timestamp,
                    src_ip=alert.src_ip,
                    dst_ip=alert.dst_ip,
                    source=self.name,
                    label=True,  # signature match = confirmed anomaly
                    confidence=confidence,
                    event_type=event_type,
                    mitre_attack_id=alert.mitre_attack_id,
                )
            )

        log.info(
            "suricata_labels_generated",
            n_alerts=len(alerts),
            n_labels=len(labels),
            min_confidence=self.min_confidence,
        )
        return labels

    def _normalize_input(self, raw_data: Any) -> list[SuricataAlert]:
        """Convert various input types into a list of SuricataAlert objects.

        Handles:
        - list[SuricataAlert]: pass through
        - list[dict]: parse as EVE JSON dicts
        - str/Path: read as EVE JSON file (one JSON per line)
        """
        if isinstance(raw_data, str | Path):
            return self._parse_eve_file(Path(raw_data))

        if isinstance(raw_data, list) and raw_data:
            if isinstance(raw_data[0], SuricataAlert):
                return raw_data
            if isinstance(raw_data[0], dict):
                return [self._parse_eve_dict(d) for d in raw_data]

        return []

    @staticmethod
    def _parse_eve_dict(data: dict[str, Any]) -> SuricataAlert:
        """Parse a single EVE JSON alert dict into a SuricataAlert."""
        alert_data = data.get("alert", {})
        src_data = data.get("src_ip", "")
        dst_data = data.get("dest_ip", "")

        # Extract MITRE ATT&CK ID from metadata if present
        mitre_id = None
        metadata = alert_data.get("metadata", [])
        for item in metadata:
            if isinstance(item, list) and len(item) >= 2:
                if item[0] == "mitre_attack_id":
                    mitre_id = item[1]
                    break

        return SuricataAlert(
            timestamp=data.get("timestamp"),
            src_ip=src_data,
            dst_ip=dst_data,
            src_port=data.get("src_port"),
            dst_port=data.get("dest_port"),
            protocol=data.get("proto", "tcp"),
            alert_signature=alert_data.get("signature", ""),
            alert_category=alert_data.get("category", ""),
            alert_severity=alert_data.get("severity", 3),
            rule_id=str(alert_data.get("signature_id", "")),
            mitre_attack_id=mitre_id,
            flow_id=str(data.get("flow_id", "")),
        )

    def _parse_eve_file(self, filepath: Path) -> list[SuricataAlert]:
        """Parse an EVE JSON file (one JSON object per line)."""
        alerts: list[SuricataAlert] = []
        if not filepath.exists():
            log.warning("eve_file_not_found", path=str(filepath))
            return alerts

        for line in filepath.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alerts.append(self._parse_eve_dict(data))
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("eve_parse_error", error=str(exc))

        return alerts
