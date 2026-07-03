"""Label importer: convert Darktrace alerts into supervised labels.

Transforms DarktraceAlert objects into SupervisedLabel objects that can be
used by the temporal alignment module. Handles deduplication and confidence
scoring based on alert severity.
"""

from __future__ import annotations

from datetime import datetime

import structlog

from src.models import DarktraceAlert, SupervisedLabel

log = structlog.get_logger()

# Severity → confidence mapping
SEVERITY_CONFIDENCE: dict[str, float] = {
    "critical": 1.0,
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
}

# Severity → event type mapping (Darktrace categories → KhaiNet event types)
CATEGORY_TO_EVENT_TYPE: dict[str, str] = {
    "exfiltration": "exfiltration",
    "c2_beaconing": "c2_beaconing",
    "lateral_movement": "lateral_movement",
    "dns_tunneling": "dns_tunneling",
    "scan": "scan",
}


class LabelImporter:
    """Import and convert Darktrace alerts into supervised labels.

    Args:
        min_severity: Minimum severity to include (filters out low-severity noise).
        deduplicate: If True, remove duplicate alerts (same src/dst/time).
    """

    def __init__(
        self,
        min_severity: str = "low",
        deduplicate: bool = True,
    ) -> None:
        self.min_severity = min_severity
        self.deduplicate = deduplicate
        self._severity_order = ["low", "medium", "high", "critical"]

    def _severity_rank(self, severity: str) -> int:
        """Return numeric rank for severity (0=low, 3=critical)."""
        try:
            return self._severity_order.index(severity.lower())
        except ValueError:
            return 0

    def _passes_filter(self, alert: DarktraceAlert) -> bool:
        """Check if an alert passes the minimum severity filter."""
        min_rank = self._severity_rank(self.min_severity)
        alert_rank = self._severity_rank(alert.severity)
        return alert_rank >= min_rank

    def import_labels(
        self,
        alerts: list[DarktraceAlert],
    ) -> list[SupervisedLabel]:
        """Convert Darktrace alerts into supervised labels.

        Each alert becomes a SupervisedLabel with label=True (it's a confirmed
        Darktrace detection). Confidence is derived from severity.

        Args:
            alerts: List of DarktraceAlert objects.

        Returns:
            List of SupervisedLabel objects.
        """
        labels: list[SupervisedLabel] = []
        seen_keys: set[tuple[str, str, float]] = set()

        for alert in alerts:
            if not self._passes_filter(alert):
                continue

            # Deduplication key: src_ip + dst_ip + timestamp (rounded to second)
            dedup_key = (
                alert.src_ip,
                alert.dst_ip,
                round(alert.ts_epoch),
            )
            if self.deduplicate and dedup_key in seen_keys:
                continue
            if self.deduplicate:
                seen_keys.add(dedup_key)

            confidence = SEVERITY_CONFIDENCE.get(alert.severity, 0.5)
            event_type = CATEGORY_TO_EVENT_TYPE.get(alert.category, "anomaly")

            labels.append(
                SupervisedLabel(
                    event_id=f"label-{alert.alert_id}",
                    timestamp=alert.timestamp,
                    src_ip=alert.src_ip,
                    dst_ip=alert.dst_ip,
                    label=True,
                    source="darktrace",
                    darktrace_alert_id=alert.alert_id,
                    confidence=confidence,
                    event_type=event_type,
                )
            )

        log.info(
            "labels_imported",
            n_alerts=len(alerts),
            n_labels=len(labels),
            min_severity=self.min_severity,
            deduplicated=self.deduplicate,
        )
        return labels

    def import_from_time_range(
        self,
        alerts: list[DarktraceAlert],
        from_time: datetime,
        to_time: datetime,
    ) -> list[SupervisedLabel]:
        """Import labels filtered by a time range.

        Args:
            alerts: List of DarktraceAlert objects.
            from_time: Start timestamp (inclusive).
            to_time: End timestamp (exclusive).

        Returns:
            Filtered list of SupervisedLabel objects.
        """
        filtered = [a for a in alerts if from_time <= a.timestamp < to_time]
        return self.import_labels(filtered)
