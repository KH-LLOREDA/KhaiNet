"""Tests for the Redis session manager."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.models import Alert
from src.state_manager import Session, SessionManager


@pytest.mark.asyncio
async def test_session_add_and_get_recent():
    """Session stores and retrieves alerts."""
    now = datetime.now(timezone.utc)
    session = Session(entity="test-ip")

    alert1 = Alert(
        alert_id="a1",
        timestamp=now,
        source="s1",
        source_type="anomaly",
        severity_raw=50,
        confidence=0.8,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="scan",
    )
    alert2 = Alert(
        alert_id="a2",
        timestamp=now,
        source="s2",
        source_type="anomaly",
        severity_raw=60,
        confidence=0.85,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="exfiltration",
    )

    session.add_alert(alert1)
    session.add_alert(alert2)

    assert len(session.alerts) == 2
    recent = session.get_recent(window_seconds=300)
    assert len(recent) == 2


@pytest.mark.asyncio
async def test_session_get_recent_filters_old():
    """Session filters out alerts older than the window."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    session = Session(entity="test-ip")

    old_alert = Alert(
        alert_id="old",
        timestamp=now - timedelta(minutes=10),
        source="s1",
        source_type="anomaly",
        severity_raw=50,
        confidence=0.8,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="scan",
    )
    new_alert = Alert(
        alert_id="new",
        timestamp=now,
        source="s2",
        source_type="anomaly",
        severity_raw=60,
        confidence=0.85,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="exfiltration",
    )

    session.add_alert(old_alert)
    session.add_alert(new_alert)

    recent = session.get_recent(window_seconds=300)
    assert len(recent) == 1
    assert recent[0].alert_id == "new"


@pytest.mark.asyncio
async def test_session_manager_update():
    """Session manager creates and updates sessions."""
    now = datetime.now(timezone.utc)
    mgr = SessionManager(session_timeout_seconds=1800)

    alert = Alert(
        alert_id="a1",
        timestamp=now,
        source="s1",
        source_type="anomaly",
        severity_raw=50,
        confidence=0.8,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="scan",
    )

    session = await mgr.update("test-ip", alert)
    assert len(session.alerts) == 1

    alert2 = Alert(
        alert_id="a2",
        timestamp=now,
        source="s2",
        source_type="anomaly",
        severity_raw=60,
        confidence=0.85,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="exfiltration",
    )
    session = await mgr.update("test-ip", alert2)
    assert len(session.alerts) == 2


@pytest.mark.asyncio
async def test_session_manager_close():
    """Session manager closes and removes sessions."""
    now = datetime.now(timezone.utc)
    mgr = SessionManager(session_timeout_seconds=1800)

    alert = Alert(
        alert_id="a1",
        timestamp=now,
        source="s1",
        source_type="anomaly",
        severity_raw=50,
        confidence=0.8,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="scan",
    )

    await mgr.update("test-ip", alert)
    closed = await mgr.close_session("test-ip")
    assert closed is not None
    assert len(closed.alerts) == 1

    # Session should no longer exist
    session = await mgr.get_session("test-ip")
    assert session is None


@pytest.mark.asyncio
async def test_session_manager_get_all_entities():
    """Session manager returns all active entities."""
    now = datetime.now(timezone.utc)
    mgr = SessionManager(session_timeout_seconds=1800)

    for ip in ["ip1", "ip2", "ip3"]:
        alert = Alert(
            alert_id=f"a-{ip}",
            timestamp=now,
            source="s",
            source_type="anomaly",
            severity_raw=50,
            confidence=0.8,
            src_ip=ip,
            dst_ip="dst",
            protocol="tcp",
            event_type="scan",
        )
        await mgr.update(ip, alert)

    entities = await mgr.get_all_entities()
    assert set(entities) == {"ip1", "ip2", "ip3"}


@pytest.mark.asyncio
async def test_session_json_serialization():
    """Session can be serialized to/from JSON."""
    now = datetime.now(timezone.utc)
    session = Session(entity="test-ip")

    alert = Alert(
        alert_id="a1",
        timestamp=now,
        source="s1",
        source_type="anomaly",
        severity_raw=50,
        confidence=0.8,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="scan",
    )
    session.add_alert(alert)

    json_str = session.to_json()
    restored = Session.from_json(json_str)

    assert restored.entity == "test-ip"
    assert len(restored.alerts) == 1
    assert restored.alerts[0].alert_id == "a1"


@pytest.mark.asyncio
async def test_session_manager_with_redis(mock_redis):
    """Session manager works with Redis backend."""
    now = datetime.now(timezone.utc)
    mgr = SessionManager(redis_client=mock_redis, session_timeout_seconds=60)

    alert = Alert(
        alert_id="a1",
        timestamp=now,
        source="s1",
        source_type="anomaly",
        severity_raw=50,
        confidence=0.8,
        src_ip="test-ip",
        dst_ip="dst",
        protocol="tcp",
        event_type="scan",
    )

    await mgr.update("test-ip", alert)

    # Verify Redis was called
    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    assert call_args[1]["ex"] == 60
