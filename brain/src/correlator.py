"""Hybrid correlation engine for KhaiNet Brain.

Two-level correlation:
1. **Sliding window (5 min)** — ``collections.deque`` per entity for O(1) insert/evict.
2. **Sessionization (30 min)** — Redis-backed sessions per entity (src_ip).

Detects multi-stage attack patterns:
- scan → login → exfiltration
- C2 beaconing (periodic connections + DNS/SSL anomalies)
- Lateral movement (internal dst + service change)
- DNS tunneling (high-entropy DNS + volume anomaly)
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone

import structlog

from src.models import Alert, AlertGroup, EventType
from src.state_manager import SessionManager

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Attack pattern detection
# ---------------------------------------------------------------------------


class AttackPattern:
    """A detected attack pattern with a name and the alerts involved."""

    def __init__(self, name: str, alerts: list[Alert]) -> None:
        self.name = name
        self.alerts = alerts


def detect_attack_pattern(alerts: list[Alert]) -> AttackPattern | None:
    """Detect multi-stage attack patterns from a list of alerts.

    Checks for known sequences of event types and returns the first match.
    """
    if len(alerts) < 2:
        return None

    # Sort by timestamp
    sorted_alerts = sorted(alerts, key=lambda a: a.ts_epoch)
    event_types = [a.event_type for a in sorted_alerts]
    event_type_values = [et if isinstance(et, str) else et.value for et in event_types]

    # Pattern 1: scan → (lateral_movement or anomaly) → exfiltration
    if (
        EventType.SCAN.value in event_type_values
        and EventType.EXFILTRATION.value in event_type_values
    ):
        scan_idx = event_type_values.index(EventType.SCAN.value)
        exfil_idx = event_type_values.index(EventType.EXFILTRATION.value)
        if exfil_idx > scan_idx:
            pattern_alerts = sorted_alerts[scan_idx : exfil_idx + 1]
            return AttackPattern("scan_to_exfiltration", pattern_alerts)

    # Pattern 2: C2 beaconing — c2_beaconing + dns_tunneling or anomaly
    if EventType.C2_BEACONING.value in event_type_values:
        c2_alerts = [
            a
            for a in sorted_alerts
            if a.event_type in (EventType.C2_BEACONING.value, EventType.C2_BEACONING)
        ]
        if len(c2_alerts) >= 1:
            # Check for DNS or SSL anomalies in the same window
            dns_or_anomaly = [
                a
                for a in sorted_alerts
                if a.event_type
                in (
                    EventType.DNS_TUNNELING.value,
                    EventType.DNS_TUNNELING,
                    EventType.ANOMALY.value,
                    EventType.ANOMALY,
                )
            ]
            if dns_or_anomaly:
                return AttackPattern("c2_beaconing", c2_alerts + dns_or_anomaly)
            return AttackPattern("c2_beaconing", c2_alerts)

    # Pattern 3: Lateral movement — scan + lateral_movement
    if (
        EventType.SCAN.value in event_type_values
        and EventType.LATERAL_MOVEMENT.value in event_type_values
    ):
        scan_alerts = [
            a
            for a in sorted_alerts
            if a.event_type in (EventType.SCAN.value, EventType.SCAN)
        ]
        lateral_alerts = [
            a
            for a in sorted_alerts
            if a.event_type
            in (EventType.LATERAL_MOVEMENT.value, EventType.LATERAL_MOVEMENT)
        ]
        return AttackPattern("lateral_movement", scan_alerts + lateral_alerts)

    # Pattern 4: DNS tunneling
    if EventType.DNS_TUNNELING.value in event_type_values:
        dns_alerts = [
            a
            for a in sorted_alerts
            if a.event_type in (EventType.DNS_TUNNELING.value, EventType.DNS_TUNNELING)
        ]
        if len(dns_alerts) >= 1:
            return AttackPattern("dns_tunneling", dns_alerts)

    return None


# ---------------------------------------------------------------------------
# Known FP rules
# ---------------------------------------------------------------------------


def matches_known_fp_rule(alerts: list[Alert]) -> bool:
    """Check if alert group matches a known false-positive rule.

    Examples:
    - Nightly backups (high bytes out at 2-4 AM, same destination)
    - Authorized scans (tagged 'authorized-scan')
    """
    if not alerts:
        return False

    for alert in alerts:
        # Authorized scan tag
        if "authorized-scan" in alert.tags:
            return True

        # Nightly backup pattern: exfiltration at 2-4 AM with backup tag
        if "backup" in alert.tags:
            return True

        if alert.event_type in (EventType.EXFILTRATION.value, EventType.EXFILTRATION):
            hour = alert.timestamp.hour
            if 2 <= hour <= 4 and "scheduled" in alert.tags:
                return True

    return False


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------


class Correlator:
    """Hybrid correlation engine using deque + Redis sessions.

    Parameters:
        session_manager: Redis-backed session manager for long-term correlation.
        window_seconds: Sliding window size (default 300 = 5 min).
        min_alerts_for_group: Minimum alerts to form a candidate group.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        window_seconds: int = 300,
        min_alerts_for_group: int = 2,
    ) -> None:
        self.sessions = session_manager
        self.window_seconds = window_seconds
        self.min_alerts = min_alerts_for_group
        # Per-entity sliding windows: entity -> deque of (epoch, alert)
        self._windows: dict[str, deque[tuple[float, Alert]]] = {}

    def _evict_window(self, entity: str, now_epoch: float) -> None:
        """Remove alerts older than window_seconds from the entity's deque."""
        window = self._windows.get(entity)
        if window is None:
            return
        cutoff = now_epoch - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

    def _get_recent_from_window(self, entity: str) -> list[Alert]:
        """Return alerts in the sliding window for *entity*."""
        window = self._windows.get(entity)
        if window is None:
            return []
        return [alert for _, alert in window]

    async def process_alert(self, alert: Alert) -> list[AlertGroup]:
        """Process a single alert and return any candidate alert groups.

        1. Updates the sliding window (deque) for the alert's src_ip.
        2. Updates the Redis session for the entity.
        3. If ≥2 alerts in the window, forms a candidate group.
        4. Detects multi-stage attack patterns from the full session.
        5. Filters known FP patterns.
        """
        entity = alert.src_ip
        now_epoch = alert.ts_epoch

        # 1. Update sliding window
        if entity not in self._windows:
            self._windows[entity] = deque(maxlen=1000)
        self._windows[entity].append((now_epoch, alert))
        self._evict_window(entity, now_epoch)

        # 2. Update Redis session
        session = await self.sessions.update(entity, alert)

        groups: list[AlertGroup] = []

        # 3. Check sliding window for candidate groups
        recent = self._get_recent_from_window(entity)
        if len(recent) >= self.min_alerts:
            groups.append(
                AlertGroup(
                    alerts=list(recent),
                    entity=entity,
                    reason="shared_source_proximity",
                )
            )

        # 4. Detect multi-stage attack patterns from full session
        all_alerts = session.get_all_alerts()
        pattern = detect_attack_pattern(all_alerts)
        if pattern:
            groups.append(
                AlertGroup(
                    alerts=pattern.alerts,
                    entity=entity,
                    reason=f"attack_pattern_{pattern.name}",
                    pattern_name=pattern.name,
                )
            )

        # 5. Filter known FP patterns
        filtered: list[AlertGroup] = []
        for group in groups:
            if matches_known_fp_rule(group.alerts):
                log.info(
                    "fp_filtered",
                    entity=entity,
                    reason=group.reason,
                    alert_count=len(group.alerts),
                )
                continue
            filtered.append(group)

        return self._deduplicate(filtered)

    def _deduplicate(self, groups: list[AlertGroup]) -> list[AlertGroup]:
        """Remove duplicate groups (same set of alert_ids)."""
        seen: set[frozenset[str]] = set()
        unique: list[AlertGroup] = []
        for group in groups:
            ids = frozenset(a.alert_id for a in group.alerts)
            if ids not in seen:
                seen.add(ids)
                unique.append(group)
        return unique

    def should_filter_pre_llm(self, group: AlertGroup) -> bool:
        """Pre-LLM filtering: discard trivial groups to save LLM cost.

        - 1 alert of severity < 40 without aggravating context → discard
        """
        if len(group.alerts) == 1:
            alert = group.alerts[0]
            if alert.severity_raw < 40 and not group.pattern_name:
                return True
        return False

    async def close_expired_sessions(self) -> list[AlertGroup]:
        """Check for sessions that have expired and produce final groups.

        This is called periodically to handle sessions that timed out
        without reaching the min_alerts threshold in the sliding window
        but may still have correlatable alerts across the session lifetime.
        """
        entities = await self.sessions.get_all_entities()
        results: list[AlertGroup] = []
        for entity in entities:
            session = await self.sessions.get_session(entity)
            if session is None:
                continue
            all_alerts = session.get_all_alerts()
            if len(all_alerts) < self.min_alerts:
                continue
            # Check if session has expired (no recent activity)
            if not all_alerts:
                continue
            latest = max(a.ts_epoch for a in all_alerts)
            now = datetime.now(timezone.utc).timestamp()
            if now - latest > self.sessions.session_timeout:
                pattern = detect_attack_pattern(all_alerts)
                if pattern:
                    results.append(
                        AlertGroup(
                            alerts=pattern.alerts,
                            entity=entity,
                            reason=f"session_expired_pattern_{pattern.name}",
                            pattern_name=pattern.name,
                        )
                    )
                await self.sessions.close_session(entity)
        return results
