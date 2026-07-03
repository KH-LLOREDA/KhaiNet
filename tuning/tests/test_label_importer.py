"""Tests for the label importer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.label_importer import LabelImporter
from src.models import DarktraceAlert


class TestImportLabels:
    def test_import_basic(self, sample_darktrace_alerts):
        importer = LabelImporter()
        labels = importer.import_labels(sample_darktrace_alerts)
        assert len(labels) == len(sample_darktrace_alerts)
        for lbl in labels:
            assert lbl.label is True
            assert lbl.source == "darktrace"
            assert lbl.darktrace_alert_id is not None

    def test_severity_confidence_mapping(self, sample_darktrace_alerts):
        importer = LabelImporter(min_severity="low")
        labels = importer.import_labels(sample_darktrace_alerts)
        for lbl, alert in zip(labels, sample_darktrace_alerts):
            if alert.severity == "critical":
                assert lbl.confidence == 1.0
            elif alert.severity == "high":
                assert lbl.confidence == 0.9
            elif alert.severity == "medium":
                assert lbl.confidence == 0.7
            elif alert.severity == "low":
                assert lbl.confidence == 0.5

    def test_severity_filter(self, sample_darktrace_alerts):
        importer = LabelImporter(min_severity="high")
        labels = importer.import_labels(sample_darktrace_alerts)
        # Only high and critical should pass
        for lbl in labels:
            # Find the original alert
            orig = next(
                a
                for a in sample_darktrace_alerts
                if a.alert_id == lbl.darktrace_alert_id
            )
            assert orig.severity in ("high", "critical")

    def test_deduplication(self, now_utc, src_ip_a, dst_ip_a):
        """Duplicate alerts (same IPs + timestamp) should be deduplicated."""
        alert1 = DarktraceAlert(
            alert_id="dt-1",
            timestamp=now_utc,
            model_name="test",
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            severity="high",
            category="exfiltration",
        )
        alert2 = DarktraceAlert(
            alert_id="dt-2",
            timestamp=now_utc,  # Same timestamp
            model_name="test",
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            severity="high",
            category="exfiltration",
        )
        importer = LabelImporter(deduplicate=True)
        labels = importer.import_labels([alert1, alert2])
        assert len(labels) == 1

    def test_no_deduplication(self, now_utc, src_ip_a, dst_ip_a):
        alert1 = DarktraceAlert(
            alert_id="dt-1",
            timestamp=now_utc,
            model_name="test",
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            severity="high",
            category="exfiltration",
        )
        alert2 = DarktraceAlert(
            alert_id="dt-2",
            timestamp=now_utc,
            model_name="test",
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            severity="high",
            category="exfiltration",
        )
        importer = LabelImporter(deduplicate=False)
        labels = importer.import_labels([alert1, alert2])
        assert len(labels) == 2

    def test_event_type_mapping(self, sample_darktrace_alerts):
        importer = LabelImporter()
        labels = importer.import_labels(sample_darktrace_alerts)
        for lbl, alert in zip(labels, sample_darktrace_alerts):
            assert lbl.event_type == alert.category

    def test_empty_input(self):
        importer = LabelImporter()
        labels = importer.import_labels([])
        assert labels == []


class TestImportFromTimeRange:
    def test_time_range_filter(self, sample_darktrace_alerts):
        importer = LabelImporter()
        from_time = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)
        to_time = datetime(2026, 7, 1, 9, 30, 0, tzinfo=timezone.utc)
        labels = importer.import_from_time_range(
            sample_darktrace_alerts, from_time, to_time
        )
        # Alerts at 8:00, 8:30, 9:00 → 3 alerts in range
        assert len(labels) == 3
        for lbl in labels:
            assert from_time <= lbl.timestamp < to_time
