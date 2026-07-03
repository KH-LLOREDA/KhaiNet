"""Tests for the Darktrace API client."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.darktrace_client import (
    DarktraceAPIError,
    DarktraceAuthError,
    DarktraceClient,
    DarktraceRateLimitError,
)


# ---------------------------------------------------------------------------
# Mock mode tests
# ---------------------------------------------------------------------------


class TestMockMode:
    @pytest.mark.asyncio
    async def test_mock_fetch_alerts(self):
        client = DarktraceClient(mock_mode=True)
        alerts = await client.fetch_alerts()
        assert len(alerts) > 0
        assert all(hasattr(a, "alert_id") for a in alerts)
        await client.close()

    @pytest.mark.asyncio
    async def test_mock_fetch_alerts_with_time_filter(self):
        client = DarktraceClient(mock_mode=True)
        from_time = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        to_time = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = await client.fetch_alerts(from_time=from_time, to_time=to_time)
        for a in alerts:
            assert from_time <= a.timestamp <= to_time
        await client.close()

    @pytest.mark.asyncio
    async def test_mock_fetch_devices(self):
        client = DarktraceClient(mock_mode=True)
        devices = await client.fetch_devices()
        assert len(devices) > 0
        assert all("did" in d for d in devices)
        await client.close()

    @pytest.mark.asyncio
    async def test_mock_fetch_model_breaches(self):
        client = DarktraceClient(mock_mode=True)
        breaches = await client.fetch_model_breaches()
        assert len(breaches) > 0
        assert all("pbid" in b for b in breaches)
        await client.close()


# ---------------------------------------------------------------------------
# Real API error handling tests (mocked httpx)
# ---------------------------------------------------------------------------


class TestAuthErrors:
    @pytest.mark.asyncio
    async def test_auth_error_401(self):
        client = DarktraceClient(mock_mode=False, api_token="bad-token")

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        mock_http_client = MagicMock()
        mock_http_client.is_closed = False
        mock_http_client.request = AsyncMock(return_value=mock_response)
        mock_http_client.aclose = AsyncMock()
        client._client = mock_http_client

        with pytest.raises(DarktraceAuthError):
            await client.fetch_alerts()

    @pytest.mark.asyncio
    async def test_auth_error_403(self):
        client = DarktraceClient(mock_mode=False, api_token="bad-token")

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"

        mock_http_client = MagicMock()
        mock_http_client.is_closed = False
        mock_http_client.request = AsyncMock(return_value=mock_response)
        mock_http_client.aclose = AsyncMock()
        client._client = mock_http_client

        with pytest.raises(DarktraceAuthError):
            await client.fetch_alerts()


class TestRateLimitError:
    @pytest.mark.asyncio
    async def test_rate_limit_429(self):
        client = DarktraceClient(mock_mode=False, api_token="test")

        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Rate limited"

        mock_http_client = MagicMock()
        mock_http_client.is_closed = False
        mock_http_client.request = AsyncMock(return_value=mock_response)
        mock_http_client.aclose = AsyncMock()
        client._client = mock_http_client

        with pytest.raises((DarktraceRateLimitError, DarktraceAPIError)):
            await client.fetch_alerts()


class TestAPIError:
    @pytest.mark.asyncio
    async def test_server_error_500(self):
        client = DarktraceClient(mock_mode=False, api_token="test")

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        mock_http_client = MagicMock()
        mock_http_client.is_closed = False
        mock_http_client.request = AsyncMock(return_value=mock_response)
        mock_http_client.aclose = AsyncMock()
        client._client = mock_http_client

        with pytest.raises(DarktraceAPIError):
            await client.fetch_alerts()


# ---------------------------------------------------------------------------
# Pagination tests
# ---------------------------------------------------------------------------


class TestPagination:
    @pytest.mark.asyncio
    async def test_pagination_multiple_pages(self):
        client = DarktraceClient(mock_mode=False, api_token="test")

        # First response has cursor, second doesn't
        response1 = MagicMock()
        response1.status_code = 200
        response1.json.return_value = {
            "alerts": [{"pbid": "a1", "time": "2026-07-01T10:00:00Z", "model": "test"}],
            "next_cursor": "cursor-123",
        }

        response2 = MagicMock()
        response2.status_code = 200
        response2.json.return_value = {
            "alerts": [{"pbid": "a2", "time": "2026-07-01T11:00:00Z", "model": "test"}],
            "next_cursor": None,
        }

        mock_http_client = MagicMock()
        mock_http_client.is_closed = False
        mock_http_client.request = AsyncMock(side_effect=[response1, response2])
        mock_http_client.aclose = AsyncMock()
        client._client = mock_http_client

        alerts = await client.fetch_alerts()
        assert len(alerts) == 2
        await client.close()


# ---------------------------------------------------------------------------
# Rate limiter tests
# ---------------------------------------------------------------------------


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limiter_allows_burst(self):
        from src.darktrace_client import _TokenBucketRateLimiter
        import time

        limiter = _TokenBucketRateLimiter(rate=10.0)
        # Should allow 10 rapid acquires (initial tokens)
        start = time.monotonic()
        for _ in range(10):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        # 10 requests should complete quickly (within 1 second)
        assert elapsed < 1.0


# ---------------------------------------------------------------------------
# Context manager tests
# ---------------------------------------------------------------------------


class TestContextManager:
    @pytest.mark.asyncio
    async def test_context_manager(self):
        async with DarktraceClient(mock_mode=True) as client:
            alerts = await client.fetch_alerts()
            assert len(alerts) > 0


# ---------------------------------------------------------------------------
# Alert parsing tests
# ---------------------------------------------------------------------------


class TestParseAlert:
    def test_parse_raw_alert(self):
        raw = {
            "pbid": "test-pbid",
            "time": "2026-07-01T10:00:00Z",
            "model": "isolation_forest",
            "srcDevice": {"did": 1, "ip": "192.168.1.1"},
            "device": {"did": 2, "ip": "10.0.0.1"},
            "srcPort": 12345,
            "dstPort": 443,
            "protocol": "tcp",
            "category": "exfiltration",
            "severity": "high",
            "description": "Test alert",
            "priority": 3,
        }
        alert = DarktraceClient._parse_alert(raw)
        assert alert.alert_id == "test-pbid"
        assert alert.model_name == "isolation_forest"
        assert alert.protocol == "tcp"
        assert alert.severity == "high"
        # IPs should be pseudonymized (hashed)
        assert alert.src_ip != "192.168.1.1"
        assert alert.dst_ip != "10.0.0.1"
        assert len(alert.src_ip) == 64  # SHA-256 hex
