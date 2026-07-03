"""Resilient LLM client for Brain/KH7.

Features:
- httpx async client with configurable timeout
- tenacity retry (3 attempts, exponential backoff 1-10s)
- Circuit breaker (5 failures → open, 60s → half_open, 3 successes → closed)
- Semantic cache in Redis (TTL 5 min)
- Fallback graceful: if LLM fails, caller uses mathematical scoring without XAI
- Hallucination detection via schema_validator
"""

from __future__ import annotations

import hashlib
import json
import time
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
import structlog
import tenacity

from src.schema_validator import (
    SchemaValidationError,
    validate_and_check_hallucinations,
)

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    """Raised when the circuit breaker is open and calls are not allowed."""


class CircuitBreaker:
    """Simple async circuit breaker.

    States:
    - CLOSED: normal operation, calls allowed
    - OPEN: LLM is down, calls blocked, fallback should be used
    - HALF_OPEN: testing recovery, limited calls allowed

    Transitions:
    - CLOSED → OPEN: after *failure_threshold* consecutive failures
    - OPEN → HALF_OPEN: after *recovery_timeout* seconds
    - HALF_OPEN → CLOSED: after *half_open_max_calls* consecutive successes
    - HALF_OPEN → OPEN: on any failure
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        half_open_max_calls: int = 3,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0

    @property
    def state(self) -> CircuitState:
        """Current state, with automatic OPEN → HALF_OPEN transition."""
        if (
            self._state == CircuitState.OPEN
            and time.monotonic() - self._last_failure_time >= self.recovery_timeout
        ):
            self._state = CircuitState.HALF_OPEN
            self._success_count = 0
            log.info("circuit_breaker_half_open")
        return self._state

    @property
    def state_value(self) -> int:
        """Numeric state for Prometheus: 0=closed, 1=open, 2=half_open."""
        s = self.state
        if s == CircuitState.CLOSED:
            return 0
        if s == CircuitState.OPEN:
            return 1
        return 2

    def can_call(self) -> bool:
        """Check if a call is allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return self._success_count < self.half_open_max_calls
        return False

    def record_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.half_open_max_calls:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                log.info("circuit_breaker_closed")
        else:
            self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        self._last_failure_time = time.monotonic()
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._failure_count = self.failure_threshold
            log.warning("circuit_breaker_reopened")
        else:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                log.warning("circuit_breaker_opened")

    def reset(self) -> None:
        """Reset to closed state (for testing)."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0


# ---------------------------------------------------------------------------
# Semantic cache
# ---------------------------------------------------------------------------


class SemanticCache:
    """Redis-based semantic cache for LLM responses.

    Uses a hash of the alert group as cache key. TTL is configurable (default 5 min).
    Falls back to in-memory cache if Redis is not available.
    """

    def __init__(
        self,
        redis_client: Any = None,
        ttl_seconds: int = 300,
    ) -> None:
        self.redis = redis_client
        self.ttl = ttl_seconds
        self._local_cache: dict[str, str] = {}

    def _make_key(self, data: dict[str, Any]) -> str:
        """Create a deterministic cache key from the alert group data."""
        serialized = json.dumps(data, sort_keys=True, default=str)
        return f"brain:llm_cache:{hashlib.sha256(serialized.encode()).hexdigest()}"

    async def get(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Get a cached result. Returns None if not found."""
        key = self._make_key(data)
        if self.redis is not None:
            cached = await self.redis.get(key)
            if cached:
                return json.loads(cached)
            return None
        # In-memory fallback
        if key in self._local_cache:
            return json.loads(self._local_cache[key])
        return None

    async def set(self, data: dict[str, Any], result: dict[str, Any]) -> None:
        """Store a result in the cache."""
        key = self._make_key(data)
        serialized = json.dumps(result, default=str)
        if self.redis is not None:
            await self.redis.set(key, serialized, ex=self.ttl)
        else:
            self._local_cache[key] = serialized

    async def clear(self) -> None:
        """Clear the cache."""
        if self.redis is not None:
            keys = await self.redis.keys("brain:llm_cache:*")
            if keys:
                await self.redis.delete(*keys)
        else:
            self._local_cache.clear()


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------


class BrainLLMClient:
    """Resilient async client for the Brain/KH7 LLM.

    Combines httpx, tenacity retry, circuit breaker, and semantic cache.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.base_url = config.get("base_url", "http://localhost:8080")
        self.model = config.get("model", "brain-kh7-v1")
        self.timeout = config.get("timeout_seconds", 30)
        self.max_tokens = config.get("max_tokens", 2000)
        self.temperature = config.get("temperature", 0.1)

        retry_cfg = config.get("retry", {})
        self.retry_attempts = retry_cfg.get("max_attempts", 3)
        self.retry_wait_min = retry_cfg.get("wait_min", 1)
        self.retry_wait_max = retry_cfg.get("wait_max", 10)

        cb_cfg = config.get("circuit_breaker", {})
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=cb_cfg.get("failure_threshold", 5),
            recovery_timeout=cb_cfg.get("recovery_timeout", 60),
            half_open_max_calls=cb_cfg.get("half_open_max_calls", 3),
        )

        cache_cfg = config.get("semantic_cache", {})
        self.semantic_cache = SemanticCache(
            redis_client=config.get("_redis_client"),
            ttl_seconds=cache_cfg.get("ttl_seconds", 300),
        )

        self._http_client: httpx.AsyncClient | None = None
        self._system_prompt = self._load_prompt("correlation.txt")

    def _load_prompt(self, filename: str) -> str:
        """Load a prompt template from config/prompts/."""
        prompt_path = Path(__file__).parent.parent / "config" / "prompts" / filename
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")
        return ""

    def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self._http_client

    def build_prompt(
        self, alert_group: dict[str, Any], enrichment: dict[str, Any]
    ) -> str:
        """Build the user prompt from alert group and enrichment data."""
        return self._system_prompt.format(
            alert_group=json.dumps(alert_group, indent=2, default=str),
            enrichment=json.dumps(enrichment, indent=2, default=str),
        )

    def _hash_group(self, alert_group: dict[str, Any]) -> dict[str, Any]:
        """Create a cacheable representation of the alert group."""
        return {
            "alerts": alert_group.get("alerts", []),
            "entity": alert_group.get("entity"),
            "reason": alert_group.get("reason"),
        }

    async def correlate(
        self, alert_group: dict[str, Any], enrichment: dict[str, Any]
    ) -> dict[str, Any]:
        """Call the LLM to correlate an alert group.

        1. Check semantic cache
        2. Check circuit breaker
        3. Build prompt and call LLM with retry
        4. Validate output (schema + hallucination detection)
        5. Cache result

        Raises:
            CircuitBreakerOpenError: If circuit breaker is open.
            httpx.TimeoutException: If LLM times out after retries.
            SchemaValidationError: If output fails validation.
        """
        # 1. Check semantic cache
        cache_data = self._hash_group(alert_group)
        cached = await self.semantic_cache.get(cache_data)
        if cached:
            log.debug("llm_cache_hit")
            return cached

        # 2. Check circuit breaker
        if not self.circuit_breaker.can_call():
            raise CircuitBreakerOpenError("LLM circuit breaker is open")

        # 3. Build prompt
        prompt = self.build_prompt(alert_group, enrichment)

        # 4. Call LLM with retry
        start_time = time.monotonic()
        try:
            result = await self._call_with_retry(prompt)
            latency_ms = int((time.monotonic() - start_time) * 1000)

            # 5. Validate output
            validated = validate_and_check_hallucinations(
                result, alert_group, enrichment
            )

            output = validated.model_dump()
            output["_latency_ms"] = latency_ms

            # Cache result
            await self.semantic_cache.set(cache_data, output)

            self.circuit_breaker.record_success()
            log.info(
                "llm_call_success",
                latency_ms=latency_ms,
                model=self.model,
            )
            return output

        except (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.HTTPStatusError,
            SchemaValidationError,
        ) as e:
            self.circuit_breaker.record_failure()
            log.warning("llm_call_failed", error=str(e), type=type(e).__name__)
            raise

    async def _call_with_retry(self, prompt: str) -> dict[str, Any]:
        """Call the LLM API with tenacity retry."""

        @tenacity.retry(
            stop=tenacity.stop_after_attempt(self.retry_attempts),
            wait=tenacity.wait_exponential(
                min=self.retry_wait_min, max=self.retry_wait_max
            ),
            retry=tenacity.retry_if_exception_type(
                (httpx.TimeoutException, httpx.ConnectError)
            ),
            reraise=True,
        )
        async def _call() -> dict[str, Any]:
            client = self._get_http_client()
            response = await client.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": self._system_prompt.split("{alert_group}")[
                                0
                            ].strip(),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
            data = response.json()
            # Extract the content from the chat completion response
            content = data["choices"][0]["message"]["content"]
            return json.loads(content)

        return await _call()

    async def reprocess_fallback(
        self,
        incident_context: dict[str, Any],
        alert_group: dict[str, Any],
        enrichment: dict[str, Any],
    ) -> dict[str, Any]:
        """Re-process an incident that was previously handled without XAI.

        Uses the xai_fallback.txt prompt template.
        """
        if not self.circuit_breaker.can_call():
            raise CircuitBreakerOpenError("LLM circuit breaker is open")

        fallback_prompt_template = self._load_prompt("xai_fallback.txt")
        prompt = fallback_prompt_template.format(
            incident_context=json.dumps(incident_context, indent=2, default=str),
            alert_group=json.dumps(alert_group, indent=2, default=str),
            enrichment=json.dumps(enrichment, indent=2, default=str),
        )

        start_time = time.monotonic()
        try:
            result = await self._call_with_retry(prompt)
            latency_ms = int((time.monotonic() - start_time) * 1000)
            validated = validate_and_check_hallucinations(
                result, alert_group, enrichment
            )
            output = validated.model_dump()
            output["_latency_ms"] = latency_ms
            self.circuit_breaker.record_success()
            return output
        except (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.HTTPStatusError,
            SchemaValidationError,
        ):
            self.circuit_breaker.record_failure()
            raise

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
