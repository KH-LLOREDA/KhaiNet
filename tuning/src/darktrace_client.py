"""Async Darktrace API client with retry, rate limiting, and mock mode.

Uses httpx for async HTTP, tenacity for retries with exponential backoff,
and a token-bucket rate limiter (max 10 req/s by default).

When ``mock_mode=True``, returns synthetic data from ``synthetic_data.py``
instead of calling the real API. This allows the entire pipeline to run
without Darktrace infrastructure.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from src.models import DarktraceAlert
from src.synthetic_data import generate_darktrace_alerts

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class DarktraceAPIError(Exception):
    """Generic Darktrace API error."""


class DarktraceAuthError(DarktraceAPIError):
    """Authentication error (401/403)."""


class DarktraceRateLimitError(DarktraceAPIError):
    """Rate limit exceeded (429)."""


# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------


class _TokenBucketRateLimiter:
    """Simple token-bucket rate limiter for async contexts."""

    def __init__(self, rate: float) -> None:
        self._rate = rate  # tokens per second
        self._tokens = rate
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            # Not enough tokens — wait a bit and retry
            await asyncio.sleep(0.05)


# ---------------------------------------------------------------------------
# Darktrace client
# ---------------------------------------------------------------------------


class DarktraceClient:
    """Async client for the Darktrace REST API with mock mode support.

    Args:
        api_url: Base URL of the Darktrace instance.
        api_token: Bearer token for authentication.
        mock_mode: If True, return synthetic data instead of calling the API.
        timeout_seconds: HTTP request timeout.
        max_retries: Maximum retry attempts on failure.
        rate_limit_per_second: Max requests per second.
    """

    def __init__(
        self,
        api_url: str = "https://darktrace.example.com",
        api_token: str = "",
        mock_mode: bool = True,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        rate_limit_per_second: float = 10.0,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.mock_mode = mock_mode
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._rate_limiter = _TokenBucketRateLimiter(rate_limit_per_second)
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # HTTP client lifecycle
    # ------------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the underlying httpx client."""
        if self._client is None or self._client.is_closed:
            headers = {}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def __aenter__(self) -> DarktraceClient:
        await self._get_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Mock mode helpers
    # ------------------------------------------------------------------

    def _mock_alerts(
        self, from_time: datetime | None, to_time: datetime | None, count: int = 50
    ) -> list[DarktraceAlert]:
        """Generate mock alerts, optionally filtered by time range."""
        alerts = generate_darktrace_alerts(n_alerts=count, seed=42)
        if from_time is not None:
            alerts = [a for a in alerts if a.timestamp >= from_time]
        if to_time is not None:
            alerts = [a for a in alerts if a.timestamp <= to_time]
        return alerts

    def _mock_devices(self) -> list[dict[str, Any]]:
        """Generate mock device inventory with pseudonymized IPs (GDPR)."""
        import hashlib

        def _pseud_ip(i: int) -> str:
            return hashlib.sha256(f"khainet-salt:10.0.0.{i}".encode()).hexdigest()

        return [
            {
                "did": i,
                "hostname": f"host-{i}",
                "ip": _pseud_ip(i),
                "mac": f"00:1a:2b:3c:4d:{i:02x}",
                "type": "server" if i % 3 == 0 else "workstation",
                "firstSeen": "2026-06-01T00:00:00Z",
                "lastSeen": "2026-07-01T00:00:00Z",
            }
            for i in range(1, 21)
        ]

    def _mock_model_breaches(self, count: int = 30) -> list[dict[str, Any]]:
        """Generate mock model breaches."""
        from src.synthetic_data import MODEL_NAMES

        import random

        rng = random.Random(99)
        base = datetime(2026, 7, 1, tzinfo=timezone.utc)
        return [
            {
                "pbid": f"mb-{i}",
                "model": rng.choice(MODEL_NAMES),
                "modelUuid": f"uuid-{i}",
                "device": {"did": rng.randint(1, 20), "hostname": f"host-{i}"},
                "time": (
                    base + __import__("datetime").timedelta(seconds=i * 60)
                ).isoformat(),
                "score": rng.uniform(0.7, 0.99),
                "category": rng.choice(
                    ["exfiltration", "c2_beaconing", "lateral_movement"]
                ),
                "description": f"Model breach {i}",
            }
            for i in range(count)
        ]

    # ------------------------------------------------------------------
    # HTTP request with retry
    # ------------------------------------------------------------------

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, DarktraceAPIError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _request(
        self, method: str, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make an HTTP request with retry and rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API path (e.g. /api/v1/alerts).
            params: Query parameters.

        Returns:
            Parsed JSON response.

        Raises:
            DarktraceAuthError: On 401/403.
            DarktraceRateLimitError: On 429.
            DarktraceAPIError: On other HTTP errors.
        """
        await self._rate_limiter.acquire()
        client = await self._get_client()

        try:
            response = await client.request(method, path, params=params)
        except httpx.HTTPError as exc:
            log.warning("darktrace_request_failed", path=path, error=str(exc))
            raise

        if response.status_code in (401, 403):
            raise DarktraceAuthError(f"Authentication failed: {response.status_code}")
        if response.status_code == 429:
            raise DarktraceRateLimitError("Rate limit exceeded")
        if response.status_code >= 400:
            raise DarktraceAPIError(
                f"API error {response.status_code}: {response.text}"
            )

        return response.json()

    async def _paginate(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        data_key: str = "alerts",
        max_pages: int = 100,
    ) -> list[dict[str, Any]]:
        """Paginate through a cursor-based endpoint.

        Args:
            path: API path.
            params: Initial query parameters.
            data_key: Key in the response containing the data list.
            max_pages: Safety limit on number of pages.

        Returns:
            Aggregated list of items from all pages.
        """
        params = dict(params or {})
        all_items: list[dict[str, Any]] = []

        for _ in range(max_pages):
            response = await self._request("GET", path, params=params)
            items = response.get(data_key, [])
            all_items.extend(items)
            cursor = response.get("next_cursor")
            if not cursor:
                break
            params["cursor"] = cursor

        return all_items

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def fetch_alerts(
        self,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[DarktraceAlert]:
        """Fetch alerts from Darktrace (or mock data if mock_mode=True).

        Args:
            from_time: Start timestamp (inclusive).
            to_time: End timestamp (exclusive).
            filters: Additional filters (device, model, etc.).

        Returns:
            List of DarktraceAlert objects.
        """
        if self.mock_mode:
            log.info("darktrace_mock_mode", endpoint="alerts")
            return self._mock_alerts(from_time, to_time)

        params: dict[str, Any] = {}
        if from_time:
            params["from"] = from_time.isoformat()
        if to_time:
            params["to"] = to_time.isoformat()
        if filters:
            params.update(filters)

        raw_alerts = await self._paginate(
            "/api/v1/alerts", params=params, data_key="alerts"
        )
        alerts = [self._parse_alert(a) for a in raw_alerts]
        log.info("darktrace_alerts_fetched", count=len(alerts))
        return alerts

    async def fetch_model_breaches(
        self,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch model breaches from Darktrace (or mock data).

        Args:
            from_time: Start timestamp.
            to_time: End timestamp.

        Returns:
            List of raw model breach dicts.
        """
        if self.mock_mode:
            log.info("darktrace_mock_mode", endpoint="modelbreaches")
            return self._mock_model_breaches()

        params: dict[str, Any] = {}
        if from_time:
            params["from"] = from_time.isoformat()
        if to_time:
            params["to"] = to_time.isoformat()

        breaches = await self._paginate(
            "/api/v1/modelbreaches", params=params, data_key="modelbreaches"
        )
        log.info("darktrace_breaches_fetched", count=len(breaches))
        return breaches

    async def fetch_devices(self) -> list[dict[str, Any]]:
        """Fetch device inventory from Darktrace (or mock data).

        Returns:
            List of device dicts.
        """
        if self.mock_mode:
            log.info("darktrace_mock_mode", endpoint="devices")
            return self._mock_devices()

        devices = await self._paginate("/api/v1/devices", data_key="devices")
        log.info("darktrace_devices_fetched", count=len(devices))
        return devices

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_alert(raw: dict[str, Any]) -> DarktraceAlert:
        """Parse a raw API alert dict into a DarktraceAlert model.

        Handles the nested device structure from the Darktrace API.
        """
        devices = []
        if "device" in raw:
            devices.append(raw["device"])
        if "srcDevice" in raw:
            devices.append(raw["srcDevice"])

        # Pseudonymize IPs if they look like raw IPs
        import hashlib

        def _pseud(ip: str | None) -> str:
            if not ip:
                return "unknown"
            if "." in ip or ":" in ip:
                return hashlib.sha256(f"salt:{ip}".encode()).hexdigest()
            return ip

        src_device = raw.get("srcDevice", {})
        dst_device = raw.get("device", {})

        return DarktraceAlert(
            alert_id=raw.get("pbid", raw.get("alert_id", "")),
            timestamp=raw.get("time", raw.get("timestamp")),
            model_name=raw.get("model", raw.get("model_name", "unknown")),
            src_ip=_pseud(src_device.get("ip")),
            dst_ip=_pseud(dst_device.get("ip")),
            src_port=raw.get("srcPort"),
            dst_port=raw.get("dstPort"),
            protocol=raw.get("protocol", "tcp"),
            category=raw.get("category", ""),
            severity=raw.get("severity", "medium"),
            description=raw.get("description", ""),
            devices=devices,
            pbid=raw.get("pbid"),
            priority=raw.get("priority", 0),
        )
