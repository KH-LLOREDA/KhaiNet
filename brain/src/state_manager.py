"""Redis-based sessionization manager for correlation.

Maintains per-entity (src_ip) sessions with a configurable inactivity timeout.
Each session accumulates alerts and allows querying recent alerts within a window.

Uses redis.asyncio for non-blocking operations. All methods are async.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from redis.asyncio import Redis

from src.models import Alert

log = structlog.get_logger()


class Session:
    """An in-memory representation of a session for a single entity."""

    def __init__(self, entity: str, alerts: list[Alert] | None = None) -> None:
        self.entity = entity
        self.alerts: list[Alert] = list(alerts) if alerts else []

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def get_recent(self, window_seconds: int = 300) -> list[Alert]:
        """Return alerts within the last *window_seconds* from the most recent."""
        if not self.alerts:
            return []
        latest = max(a.ts_epoch for a in self.alerts)
        cutoff = latest - window_seconds
        return [a for a in self.alerts if a.ts_epoch >= cutoff]

    def get_all_alerts(self) -> list[Alert]:
        return list(self.alerts)

    def to_json(self) -> str:
        """Serialize session to JSON for Redis storage."""
        return json.dumps(
            {
                "entity": self.entity,
                "alerts": [a.model_dump(mode="json") for a in self.alerts],
            }
        )

    @classmethod
    def from_json(cls, data: str) -> Session:
        obj = json.loads(data)
        alerts = [Alert(**a) for a in obj.get("alerts", [])]
        return cls(entity=obj["entity"], alerts=alerts)


class SessionManager:
    """Manages entity sessions in Redis with TTL-based expiry.

    Each session is stored under key ``brain:session:{entity}`` with a TTL
    equal to *session_timeout_seconds*. Every alert for an entity refreshes
    the TTL, keeping active sessions alive.
    """

    def __init__(
        self,
        redis_client: Redis | None = None,
        session_timeout_seconds: int = 1800,
    ) -> None:
        self.redis = redis_client
        self.session_timeout = session_timeout_seconds
        # In-memory fallback when Redis is not available (for testing)
        self._local_sessions: dict[str, Session] = {}

    def _key(self, entity: str) -> str:
        return f"brain:session:{entity}"

    async def update(self, entity: str, alert: Alert) -> Session:
        """Add *alert* to the session for *entity* and refresh TTL.

        Returns the updated session.
        """
        if self.redis is not None:
            key = self._key(entity)
            existing = await self.redis.get(key)
            if existing:
                session = Session.from_json(existing)
            else:
                session = Session(entity=entity)
            session.add_alert(alert)
            await self.redis.set(key, session.to_json(), ex=self.session_timeout)
            return session
        # In-memory fallback
        session = self._local_sessions.get(entity)
        if session is None:
            session = Session(entity=entity)
            self._local_sessions[entity] = session
        session.add_alert(alert)
        return session

    async def get_session(self, entity: str) -> Session | None:
        """Retrieve the session for *entity* without updating TTL."""
        if self.redis is not None:
            key = self._key(entity)
            data = await self.redis.get(key)
            if data:
                return Session.from_json(data)
            return None
        return self._local_sessions.get(entity)

    async def get_recent(self, entity: str, window_seconds: int = 300) -> list[Alert]:
        """Return alerts for *entity* within the last *window_seconds*."""
        session = await self.get_session(entity)
        if session is None:
            return []
        return session.get_recent(window_seconds)

    async def close_session(self, entity: str) -> Session | None:
        """Remove and return the session for *entity*."""
        if self.redis is not None:
            key = self._key(entity)
            data = await self.redis.get(key)
            if data:
                await self.redis.delete(key)
                return Session.from_json(data)
            return None
        return self._local_sessions.pop(entity, None)

    async def get_all_entities(self) -> list[str]:
        """Return all active session entities (best-effort)."""
        if self.redis is not None:
            keys = await self.redis.keys("brain:session:*")
            return [
                k.split(b":")[-1].decode() if isinstance(k, bytes) else k.split(":")[-1]
                for k in keys
            ]
        return list(self._local_sessions.keys())

    async def cleanup_expired(self) -> int:
        """Remove expired in-memory sessions. Redis handles TTL automatically."""
        now = datetime.now(timezone.utc).timestamp()
        expired = []
        for entity, session in self._local_sessions.items():
            if not session.alerts:
                expired.append(entity)
                continue
            latest = max(a.ts_epoch for a in session.alerts)
            if now - latest > self.session_timeout:
                expired.append(entity)
        for entity in expired:
            self._local_sessions.pop(entity, None)
        return len(expired)
