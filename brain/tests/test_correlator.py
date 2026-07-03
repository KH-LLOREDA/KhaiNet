"""Tests for the correlation engine."""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.correlator import (
    AttackPattern,
    Correlator,
    detect_attack_pattern,
    matches_known_fp_rule,
)
from src.models import Alert, AlertGroup, EventType
from src.state_manager import SessionManager


@pytest.mark.asyncio
async def test_correlation_3_alerts_5min_window(three_correlated_alerts):
    """Test case 1: 3 alerts in 5 min → 1 incident with 3 alerts."""
    from src.models import Alert

    alerts = [Alert(**a) for a in three_correlated_alerts]
    session_mgr = SessionManager(session_timeout_seconds=1800)
    correlator = Correlator(session_mgr, window_seconds=300, min_alerts_for_group=2)

    groups: list[AlertGroup] = []
    for alert in alerts:
        result = await correlator.process_alert(alert)
        groups.extend(result)

    # Should produce at least one group with all 3 alerts
    assert len(groups) > 0
    largest = max(groups, key=lambda g: len(g.alerts))
    assert len(largest.alerts) >= 3


@pytest.mark.asyncio
async def test_single_low_severity_filtered(low_severity_alert_data):
    """Test case 2: single low severity alert → no incident (filtered pre-LLM)."""
    from src.models import Alert

    alert = Alert(**low_severity_alert_data)
    session_mgr = SessionManager(session_timeout_seconds=1800)
    correlator = Correlator(session_mgr, window_seconds=300, min_alerts_for_group=2)

    groups = await correlator.process_alert(alert)

    # Single alert doesn't meet min_alerts threshold
    assert len(groups) == 0

    # Even if we create a group, it should be filtered
    if groups:
        assert correlator.should_filter_pre_llm(groups[0])


@pytest.mark.asyncio
async def test_fp_detection_backup(backup_alert_data):
    """Test case 8: backup pattern → filtered as FP."""
    from src.models import Alert

    alert = Alert(**backup_alert_data)
    assert matches_known_fp_rule([alert])


@pytest.mark.asyncio
async def test_authorized_scan_filtered():
    """Authorized scan tag → FP."""
    from datetime import datetime, timezone

    alert = Alert(
        alert_id="test-1",
        timestamp=datetime.now(timezone.utc),
        source="suricata",
        source_type="signature",
        severity_raw=50,
        confidence=0.9,
        src_ip="abc123",
        dst_ip="def456",
        protocol="tcp",
        event_type="scan",
        tags=["authorized-scan"],
    )
    assert matches_known_fp_rule([alert])


def test_detect_scan_to_exfiltration_pattern(three_correlated_alerts):
    """Detect scan → anomaly → exfiltration pattern."""
    from src.models import Alert

    alerts = [Alert(**a) for a in three_correlated_alerts]
    pattern = detect_attack_pattern(alerts)
    assert pattern is not None
    assert pattern.name == "scan_to_exfiltration"
    assert len(pattern.alerts) >= 2


def test_detect_c2_beaconing_pattern():
    """Detect C2 beaconing pattern."""
    from datetime import datetime, timezone

    alerts = [
        Alert(
            alert_id="c2-1",
            timestamp=datetime.now(timezone.utc),
            source="ml-isolation-forest",
            source_type="anomaly",
            severity_raw=70,
            confidence=0.85,
            src_ip="aaa111",
            dst_ip="bbb222",
            protocol="tcp",
            event_type="c2_beaconing",
        ),
        Alert(
            alert_id="c2-2",
            timestamp=datetime.now(timezone.utc),
            source="suricata",
            source_type="signature",
            severity_raw=65,
            confidence=0.8,
            src_ip="aaa111",
            dst_ip="bbb222",
            protocol="udp",
            event_type="dns_tunneling",
        ),
    ]
    pattern = detect_attack_pattern(alerts)
    assert pattern is not None
    assert pattern.name == "c2_beaconing"


def test_detect_lateral_movement_pattern():
    """Detect lateral movement pattern."""
    from datetime import datetime, timezone

    alerts = [
        Alert(
            alert_id="lm-1",
            timestamp=datetime.now(timezone.utc),
            source="suricata",
            source_type="signature",
            severity_raw=55,
            confidence=0.8,
            src_ip="aaa111",
            dst_ip="bbb222",
            protocol="tcp",
            event_type="scan",
        ),
        Alert(
            alert_id="lm-2",
            timestamp=datetime.now(timezone.utc),
            source="ml-hmm",
            source_type="anomaly",
            severity_raw=72,
            confidence=0.85,
            src_ip="aaa111",
            dst_ip="bbb222",
            protocol="tcp",
            event_type="lateral_movement",
        ),
    ]
    pattern = detect_attack_pattern(alerts)
    assert pattern is not None
    assert pattern.name == "lateral_movement"


def test_no_pattern_single_alert():
    """Single alert should not produce a pattern."""
    from datetime import datetime, timezone

    alert = Alert(
        alert_id="single-1",
        timestamp=datetime.now(timezone.utc),
        source="suricata",
        source_type="signature",
        severity_raw=50,
        confidence=0.8,
        src_ip="aaa111",
        dst_ip="bbb222",
        protocol="tcp",
        event_type="scan",
    )
    pattern = detect_attack_pattern([alert])
    assert pattern is None


@pytest.mark.asyncio
async def test_sessionization_30min(three_correlated_alerts, now_utc):
    """Test case 7: sessionization — scan at 10:00, exfil at 10:25 → 1 incident."""
    from datetime import timedelta

    from src.models import Alert

    # Create alerts 25 minutes apart
    scan_alert = Alert(
        alert_id="scan-1",
        timestamp=now_utc,
        source="suricata",
        source_type="signature",
        severity_raw=55,
        confidence=0.8,
        src_ip="aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
        dst_ip="bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2",
        protocol="tcp",
        event_type="scan",
    )
    exfil_alert = Alert(
        alert_id="exfil-1",
        timestamp=now_utc + timedelta(minutes=25),
        source="ml-isolation-forest",
        source_type="anomaly",
        severity_raw=80,
        confidence=0.9,
        src_ip="aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
        dst_ip="bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2",
        protocol="tcp",
        event_type="exfiltration",
    )

    session_mgr = SessionManager(session_timeout_seconds=1800)
    # Update session with scan alert
    session = await session_mgr.update(scan_alert.src_ip, scan_alert)
    assert len(session.alerts) == 1

    # Update session with exfil alert 25 min later
    session = await session_mgr.update(exfil_alert.src_ip, exfil_alert)
    assert len(session.alerts) == 2

    # The session should contain both alerts
    all_alerts = session.get_all_alerts()
    event_types = [a.event_type for a in all_alerts]
    assert "scan" in event_types
    assert "exfiltration" in event_types


@pytest.mark.asyncio
async def test_deduplicate_groups():
    """Deduplicate groups with same alert IDs."""
    from datetime import datetime, timezone

    alert = Alert(
        alert_id="dedup-1",
        timestamp=datetime.now(timezone.utc),
        source="suricata",
        source_type="signature",
        severity_raw=60,
        confidence=0.8,
        src_ip="aaa111",
        dst_ip="bbb222",
        protocol="tcp",
        event_type="scan",
    )
    session_mgr = SessionManager()
    correlator = Correlator(session_mgr)
    g1 = AlertGroup(alerts=[alert], entity="aaa111", reason="r1")
    g2 = AlertGroup(alerts=[alert], entity="aaa111", reason="r2")
    result = correlator._deduplicate([g1, g2])
    assert len(result) == 1
