"""Tests for label sources (Suricata, Wazuh, MISP, Brain, Analyst, Darktrace)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.label_sources import (
    AnalystLabeler,
    BrainLabeler,
    DarktraceLabeler,
    MISPLabeler,
    SuricataLabeler,
    WazuhLabeler,
)
from src.models import (
    AnalystFeedback,
    BrainCorrelation,
    DarktraceAlert,
    MISPEvent,
    ModelScore,
    SuricataAlert,
    WazuhAlert,
)


# ---------------------------------------------------------------------------
# Suricata labeler tests
# ---------------------------------------------------------------------------


class TestSuricataLabeler:
    def test_generate_labels_from_alerts(self, now_utc, src_ip_a, dst_ip_a):
        alerts = [
            SuricataAlert(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                alert_signature="ET POLICY C2 traffic",
                alert_category="Trojan Activity",
                alert_severity=1,
            ),
            SuricataAlert(
                timestamp=now_utc + timedelta(seconds=10),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                alert_signature="ET SCAN port sweep",
                alert_category="Network Scan",
                alert_severity=3,
            ),
        ]
        labeler = SuricataLabeler(min_confidence=0.0)
        labels = labeler.generate_labels(alerts)
        assert len(labels) == 2
        for lbl in labels:
            assert lbl.source == "suricata"
            assert lbl.label is True
            assert lbl.confidence > 0

    def test_severity_confidence_mapping(self, now_utc, src_ip_a, dst_ip_a):
        alerts = [
            SuricataAlert(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                alert_severity=1,
            ),
            SuricataAlert(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                alert_severity=2,
            ),
            SuricataAlert(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                alert_severity=3,
            ),
        ]
        labeler = SuricataLabeler(min_confidence=0.0)
        labels = labeler.generate_labels(alerts)
        assert labels[0].confidence == 0.95  # severity 1
        assert labels[1].confidence == 0.80  # severity 2
        assert labels[2].confidence == 0.60  # severity 3

    def test_min_confidence_filter(self, now_utc, src_ip_a, dst_ip_a):
        alerts = [
            SuricataAlert(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                alert_severity=3,  # confidence 0.60
            ),
        ]
        labeler = SuricataLabeler(min_confidence=0.7)
        labels = labeler.generate_labels(alerts)
        assert len(labels) == 0  # filtered out

    def test_parse_eve_dict(self):
        eve_dict = {
            "timestamp": "2026-07-01T10:00:00Z",
            "event_type": "alert",
            "src_ip": "abc123",
            "dest_ip": "def456",
            "src_port": 12345,
            "dest_port": 443,
            "proto": "tcp",
            "alert": {
                "signature": "ET C2 traffic",
                "category": "Trojan Activity",
                "severity": 1,
                "signature_id": 2100001,
                "metadata": [["mitre_attack_id", "T1041"]],
            },
        }
        alert = SuricataLabeler._parse_eve_dict(eve_dict)
        assert alert.src_ip == "abc123"
        assert alert.dst_ip == "def456"
        assert alert.alert_severity == 1
        assert alert.mitre_attack_id == "T1041"

    def test_empty_input(self):
        labeler = SuricataLabeler()
        assert labeler.generate_labels([]) == []
        assert labeler.generate_labels(None) == []


# ---------------------------------------------------------------------------
# Wazuh labeler tests
# ---------------------------------------------------------------------------


class TestWazuhLabeler:
    def test_generate_labels_from_alerts(self, now_utc, src_ip_a, dst_ip_a):
        alerts = [
            WazuhAlert(
                timestamp=now_utc,
                agent_id="001",
                agent_name="web-server",
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                rule_level=9,
                rule_groups=["auth", "web"],
            ),
            WazuhAlert(
                timestamp=now_utc + timedelta(seconds=10),
                agent_id="002",
                agent_name="db-server",
                rule_level=3,
                rule_groups=["syscheck"],
            ),
        ]
        labeler = WazuhLabeler(min_rule_level=6, min_confidence=0.0)
        labels = labeler.generate_labels(alerts)
        # Only the level 9 alert passes min_rule_level=6
        assert len(labels) == 1
        assert labels[0].source == "wazuh"
        assert labels[0].label is True
        assert labels[0].confidence == 0.85  # level 9

    def test_host_only_event_lower_confidence(self, now_utc):
        alert = WazuhAlert(
            timestamp=now_utc,
            agent_id="001",
            agent_name="server",
            src_ip="",  # no network IP
            dst_ip="",
            rule_level=12,
            rule_groups=["rootcheck"],
        )
        labeler = WazuhLabeler(min_rule_level=6, min_confidence=0.0)
        labels = labeler.generate_labels([alert])
        assert len(labels) == 1
        # Confidence should be 0.95 * 0.7 = 0.665 (host-only penalty)
        assert labels[0].confidence == pytest.approx(0.665, abs=0.01)

    def test_empty_input(self):
        labeler = WazuhLabeler()
        assert labeler.generate_labels([]) == []


# ---------------------------------------------------------------------------
# MISP labeler tests
# ---------------------------------------------------------------------------


class TestMISPLabeler:
    def test_generate_labels_from_events(self, now_utc, src_ip_a, dst_ip_a):
        events = [
            MISPEvent(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                ioc_type="ip-dst",
                ioc_value="hash123",
                threat_level=1,
                tags=["c2", "botnet"],
            ),
            MISPEvent(
                timestamp=now_utc + timedelta(seconds=10),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                ioc_type="domain",
                ioc_value="hash456",
                threat_level=3,
                tags=["scan"],
            ),
        ]
        labeler = MISPLabeler(min_confidence=0.0)
        labels = labeler.generate_labels(events)
        assert len(labels) == 2
        assert labels[0].source == "misp"
        assert labels[0].label is True
        assert labels[0].confidence == 0.95  # threat level 1
        assert labels[0].event_type == "c2_beaconing"  # from tags

    def test_empty_input(self):
        labeler = MISPLabeler()
        assert labeler.generate_labels([]) == []


# ---------------------------------------------------------------------------
# Brain labeler tests
# ---------------------------------------------------------------------------


class TestBrainLabeler:
    def test_generate_labels_from_correlations(self, now_utc, src_ip_a, dst_ip_a):
        correlations = [
            BrainCorrelation(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                mitre_tactic="Exfiltration",
                mitre_attack_id="T1041",
                confidence=0.8,
            ),
            BrainCorrelation(
                timestamp=now_utc + timedelta(seconds=10),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                mitre_tactic="Command and Control",
                mitre_attack_id="T1041",
                confidence=0.6,
            ),
        ]
        labeler = BrainLabeler(min_confidence=0.0)
        labels = labeler.generate_labels(correlations)
        assert len(labels) == 2
        assert labels[0].source == "brain"
        assert labels[0].label is True
        # Confidence scaled: 0.8 * 0.8 = 0.64
        assert labels[0].confidence == pytest.approx(0.64, abs=0.01)
        assert labels[0].event_type == "exfiltration"

    def test_confidence_scale_filter(self, now_utc, src_ip_a, dst_ip_a):
        corr = BrainCorrelation(
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            mitre_tactic="Discovery",
            confidence=0.3,
        )
        labeler = BrainLabeler(min_confidence=0.3, confidence_scale=0.8)
        labels = labeler.generate_labels([corr])
        # 0.3 * 0.8 = 0.24 < 0.3 → filtered
        assert len(labels) == 0


# ---------------------------------------------------------------------------
# Analyst labeler tests
# ---------------------------------------------------------------------------


class TestAnalystLabeler:
    def test_generate_labels_from_feedback(self, now_utc, src_ip_a, dst_ip_a):
        feedbacks = [
            AnalystFeedback(
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                label=True,
                analyst_id="analyst-1",
                event_id="evt-001",
            ),
            AnalystFeedback(
                timestamp=now_utc + timedelta(seconds=10),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                label=False,
                analyst_id="analyst-2",
                event_id="evt-002",
            ),
        ]
        labeler = AnalystLabeler()
        labels = labeler.generate_labels(feedbacks)
        assert len(labels) == 2
        assert labels[0].source == "analyst"
        assert labels[0].label is True
        assert labels[0].confidence == 1.0  # human = max confidence
        assert labels[1].label is False
        assert labels[1].confidence == 1.0


# ---------------------------------------------------------------------------
# Darktrace labeler tests
# ---------------------------------------------------------------------------


class TestDarktraceLabeler:
    def test_generate_labels_from_alerts(self, sample_darktrace_alerts):
        labeler = DarktraceLabeler(min_confidence=0.0)
        labels = labeler.generate_labels(sample_darktrace_alerts)
        assert len(labels) == len(sample_darktrace_alerts)
        for lbl in labels:
            assert lbl.source == "darktrace"
            assert lbl.label is True

    def test_disabled_by_default_in_config(self):
        # The Darktrace labeler is still usable, but config sets enabled=false
        labeler = DarktraceLabeler()
        assert labeler.name == "darktrace"


# ---------------------------------------------------------------------------
# Match to events tests
# ---------------------------------------------------------------------------


class TestMatchToEvents:
    def test_match_by_ip_and_time(self, now_utc, src_ip_a, dst_ip_a):
        from src.label_sources.base import LabelSource
        from src.models import WeakLabel

        # Create a concrete label source for testing match_to_events
        class TestSource(LabelSource):
            def generate_labels(self, raw_data):
                return raw_data

        source = TestSource("test")

        events = [
            ModelScore(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.8,
            ),
            ModelScore(
                event_id="evt-2",
                timestamp=now_utc + timedelta(seconds=120),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.3,
            ),
        ]

        labels = [
            WeakLabel(
                event_id="",
                timestamp=now_utc + timedelta(seconds=5),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="test",
                label=True,
                confidence=0.9,
            ),
        ]

        matched = source.match_to_events(labels, events, window_seconds=60.0)
        assert len(matched) == 1
        assert matched[0].event_id == "evt-1"  # closest in time

    def test_no_match_different_ip(
        self, now_utc, src_ip_a, dst_ip_a, src_ip_b, dst_ip_b
    ):
        from src.label_sources.base import LabelSource
        from src.models import WeakLabel

        class TestSource(LabelSource):
            def generate_labels(self, raw_data):
                return raw_data

        source = TestSource("test")

        events = [
            ModelScore(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.8,
            ),
        ]

        labels = [
            WeakLabel(
                event_id="",
                timestamp=now_utc,
                src_ip=src_ip_b,  # different IP
                dst_ip=dst_ip_b,
                source="test",
                label=True,
                confidence=0.9,
            ),
        ]

        matched = source.match_to_events(labels, events, window_seconds=60.0)
        assert len(matched) == 0  # no match — different IPs
