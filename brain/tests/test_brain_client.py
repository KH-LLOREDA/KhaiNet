"""Tests for the Brain LLM client with circuit breaker and semantic cache."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.brain_client import (
    BrainLLMClient,
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    SemanticCache,
)
from src.schema_validator import SchemaValidationError


# ---------------------------------------------------------------------------
# Circuit breaker tests
# ---------------------------------------------------------------------------


def test_circuit_breaker_starts_closed():
    cb = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
    assert cb.state == CircuitState.CLOSED
    assert cb.can_call()


def test_circuit_breaker_opens_after_threshold():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert not cb.can_call()


def test_circuit_breaker_half_open_after_timeout():
    import time

    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
    cb.record_failure()
    cb.record_failure()
    cb.record_failure()
    # Right after failures, state should be OPEN (timeout not elapsed yet)
    assert cb.state == CircuitState.OPEN
    # Wait for recovery timeout
    time.sleep(1.1)
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.can_call()


def test_circuit_breaker_closes_after_successes():
    import time

    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1, half_open_max_calls=2)
    for _ in range(3):
        cb.record_failure()
    time.sleep(1.1)
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_success()
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_circuit_breaker_reopens_on_half_open_failure():
    import time

    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
    for _ in range(3):
        cb.record_failure()
    time.sleep(1.1)
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# Semantic cache tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_semantic_cache_set_get():
    cache = SemanticCache(ttl_seconds=60)
    data = {"alerts": [{"id": "1"}], "entity": "test"}
    result = {"title": "test incident"}

    await cache.set(data, result)
    cached = await cache.get(data)
    assert cached == result


@pytest.mark.asyncio
async def test_semantic_cache_miss():
    cache = SemanticCache(ttl_seconds=60)
    data = {"alerts": [{"id": "1"}]}
    cached = await cache.get(data)
    assert cached is None


@pytest.mark.asyncio
async def test_semantic_cache_with_redis(mock_redis):
    cache = SemanticCache(redis_client=mock_redis, ttl_seconds=60)
    data = {"alerts": [{"id": "1"}]}
    result = {"title": "cached"}

    # Mock Redis returns None on first get, then the stored value
    mock_redis.get = AsyncMock(side_effect=[None, json.dumps(result)])
    mock_redis.set = AsyncMock()

    cached = await cache.get(data)
    assert cached is None

    await cache.set(data, result)
    cached = await cache.get(data)
    assert cached == result


# ---------------------------------------------------------------------------
# LLM client tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_llm_client_success(test_config, valid_llm_output, mock_llm_response):
    """Test case: LLM returns valid output."""
    config = test_config["llm"].copy()
    config["_redis_client"] = None
    client = BrainLLMClient(config)

    # Mock the HTTP client
    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(return_value=mock_llm_response)
    client._http_client = mock_http

    alert_group = {
        "alerts": [
            {
                "alert_id": "1",
                "src_ip": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            }
        ],
        "entity": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "reason": "test",
    }
    enrichment = {"asset_info": {"hostname": "SRV-DB-01"}}

    result = await client.correlate(alert_group, enrichment)

    assert result["title"] == valid_llm_output["title"]
    assert result["confidence"] == 0.88
    assert "_latency_ms" in result
    assert client.circuit_breaker.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_llm_client_timeout_fallback(test_config):
    """Test case 3: LLM timeout → fallback graceful."""
    config = test_config["llm"].copy()
    config["_redis_client"] = None
    client = BrainLLMClient(config)

    # Mock HTTP client that times out
    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    client._http_client = mock_http

    alert_group = {
        "alerts": [
            {
                "alert_id": "1",
                "src_ip": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
            }
        ],
        "entity": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
        "reason": "test",
    }
    enrichment = {}

    with pytest.raises(httpx.TimeoutException):
        await client.correlate(alert_group, enrichment)

    # Circuit breaker should have recorded a failure
    assert client.circuit_breaker._failure_count > 0


@pytest.mark.asyncio
async def test_llm_client_hallucination_detection(test_config, hallucinated_llm_output):
    """Test case 4: LLM hallucinates IPs → SchemaValidationError."""
    config = test_config["llm"].copy()
    config["_redis_client"] = None
    client = BrainLLMClient(config)

    # Mock response with hallucinated IPs
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b'{"data": "resp"}'
    mock_response.json.return_value = {
        "choices": [{"message": {"content": json.dumps(hallucinated_llm_output)}}]
    }
    mock_response.raise_for_status = MagicMock()

    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(return_value=mock_response)
    client._http_client = mock_http

    alert_group = {
        "alerts": [
            {
                "alert_id": "1",
                "src_ip": "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
            }
        ],
        "entity": "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
        "reason": "test",
    }
    enrichment = {}

    with pytest.raises(SchemaValidationError):
        await client.correlate(alert_group, enrichment)


@pytest.mark.asyncio
async def test_circuit_breaker_open_blocks_calls(test_config):
    """Test case 5: circuit breaker open → all correlations use fallback."""
    config = test_config["llm"].copy()
    config["_redis_client"] = None
    config["circuit_breaker"]["failure_threshold"] = 2
    client = BrainLLMClient(config)

    # Force circuit breaker open with long recovery timeout
    client.circuit_breaker._failure_count = 5
    client.circuit_breaker._state = CircuitState.OPEN
    client.circuit_breaker.recovery_timeout = 999  # Won't recover during test
    client.circuit_breaker._last_failure_time = float(
        "inf"
    )  # Ensure timeout won't trigger

    alert_group = {
        "alerts": [{"alert_id": "1", "src_ip": "abc"}],
        "entity": "abc",
        "reason": "test",
    }

    with pytest.raises(CircuitBreakerOpenError):
        await client.correlate(alert_group, {})


@pytest.mark.asyncio
async def test_llm_client_cache_hit(test_config, valid_llm_output, mock_llm_response):
    """Semantic cache returns cached result without calling LLM."""
    config = test_config["llm"].copy()
    config["_redis_client"] = None
    client = BrainLLMClient(config)

    # Pre-populate cache
    alert_group = {
        "alerts": [
            {
                "alert_id": "1",
                "src_ip": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
                "raw_event": {"hostname": "SRV-DB-01"},
            }
        ],
        "entity": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
        "reason": "test",
        "entities": {"src_hosts": ["SRV-DB-01"]},
    }
    enrichment = {"asset_info": {"hostname": "SRV-DB-01"}}

    # First call populates cache
    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(return_value=mock_llm_response)
    client._http_client = mock_http

    result1 = await client.correlate(alert_group, enrichment)
    assert result1["title"] == valid_llm_output["title"]

    # Second call should hit cache (post not called again)
    call_count_before = mock_http.post.call_count
    result2 = await client.correlate(alert_group, enrichment)
    assert mock_http.post.call_count == call_count_before  # No new HTTP call
    assert result2["title"] == valid_llm_output["title"]
