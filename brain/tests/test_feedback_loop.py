"""Tests for the feedback loop module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from src.feedback_loop import FeedbackLoop, _safe_eval
from src.models import AnalystFeedback, FeedbackVerdict


# ---------------------------------------------------------------------------
# _safe_eval tests
# ---------------------------------------------------------------------------


def test_safe_eval_dict_passthrough():
    """Dict input is returned as-is."""
    data = {"incident_id": "123", "reason": "test"}
    assert _safe_eval(data) == data


def test_safe_eval_json_string():
    """JSON string is parsed correctly."""
    data = json.dumps({"incident_id": "123", "reason": "test"})
    result = _safe_eval(data)
    assert result["incident_id"] == "123"
    assert result["reason"] == "test"


def test_safe_eval_bytes():
    """Bytes input is decoded and parsed as JSON."""
    data = json.dumps({"incident_id": "456"}).encode("utf-8")
    result = _safe_eval(data)
    assert result["incident_id"] == "456"


def test_safe_eval_invalid_json():
    """Invalid JSON string returns raw fallback."""
    result = _safe_eval("not valid json at all")
    assert result == {"raw": "not valid json at all"}


def test_safe_eval_other_type():
    """Non-string/dict/bytes input returns raw string."""
    result = _safe_eval(42)
    assert result == {"raw": "42"}


# ---------------------------------------------------------------------------
# FeedbackLoop tests (in-memory, no Redis)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_false_positive():
    """FP feedback registers an FP pattern."""
    loop = FeedbackLoop()
    feedback = AnalystFeedback(
        incident_id="inc-001",
        analyst="analyst1",
        verdict=FeedbackVerdict.FALSE_POSITIVE,
        reason="Scheduled backup, not exfiltration",
    )
    await loop.ingest_feedback(feedback)

    patterns = await loop.get_fp_patterns()
    assert len(patterns) == 1
    assert patterns[0]["incident_id"] == "inc-001"
    assert patterns[0]["reason"] == "Scheduled backup, not exfiltration"


@pytest.mark.asyncio
async def test_ingest_true_positive():
    """TP feedback reinforces the pattern."""
    loop = FeedbackLoop()
    feedback = AnalystFeedback(
        incident_id="inc-002",
        analyst="analyst1",
        verdict=FeedbackVerdict.TRUE_POSITIVE,
    )
    await loop.ingest_feedback(feedback)

    patterns = await loop.get_tp_patterns()
    assert len(patterns) == 1
    assert patterns[0]["incident_id"] == "inc-002"


@pytest.mark.asyncio
async def test_ingest_needs_review():
    """Needs-review feedback is logged but doesn't register a pattern."""
    loop = FeedbackLoop()
    feedback = AnalystFeedback(
        incident_id="inc-003",
        analyst="analyst1",
        verdict=FeedbackVerdict.NEEDS_REVIEW,
        reason="Unclear, needs manual investigation",
    )
    await loop.ingest_feedback(feedback)

    # No FP or TP patterns registered
    assert len(await loop.get_fp_patterns()) == 0
    assert len(await loop.get_tp_patterns()) == 0


@pytest.mark.asyncio
async def test_ingest_severity_adjustment():
    """Severity adjustment is recorded for calibration."""
    loop = FeedbackLoop()
    feedback = AnalystFeedback(
        incident_id="inc-004",
        analyst="analyst1",
        verdict=FeedbackVerdict.TRUE_POSITIVE,
        original_severity=80,
        adjusted_severity=65,
        severity_adjustment=-15,
    )
    await loop.ingest_feedback(feedback)

    calibrations = await loop.get_severity_calibrations()
    assert len(calibrations) == 1
    assert calibrations[0]["original_severity"] == 80
    assert calibrations[0]["adjusted_severity"] == 65
    assert calibrations[0]["adjustment"] == -15


@pytest.mark.asyncio
async def test_multiple_fp_patterns():
    """Multiple FP patterns are accumulated."""
    loop = FeedbackLoop()
    for i in range(3):
        feedback = AnalystFeedback(
            incident_id=f"inc-{i:03d}",
            analyst="analyst1",
            verdict=FeedbackVerdict.FALSE_POSITIVE,
            reason=f"FP reason {i}",
        )
        await loop.ingest_feedback(feedback)

    patterns = await loop.get_fp_patterns()
    assert len(patterns) == 3


# ---------------------------------------------------------------------------
# FeedbackLoop tests (with mock Redis)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_fp_with_redis(mock_redis):
    """FP feedback stored in Redis via lpush with JSON."""
    loop = FeedbackLoop(redis_client=mock_redis)
    feedback = AnalystFeedback(
        incident_id="inc-redis-001",
        analyst="analyst1",
        verdict=FeedbackVerdict.FALSE_POSITIVE,
        reason="Test FP",
    )
    await loop.ingest_feedback(feedback)

    mock_redis.lpush.assert_called_once()
    call_args = mock_redis.lpush.call_args
    # First positional arg is the key, second is the JSON string
    assert call_args[0][0] == "brain:fp_patterns"
    stored = json.loads(call_args[0][1])
    assert stored["incident_id"] == "inc-redis-001"
    assert stored["reason"] == "Test FP"


@pytest.mark.asyncio
async def test_get_fp_patterns_from_redis(mock_redis):
    """get_fp_patterns retrieves and parses JSON from Redis."""
    stored_patterns = [
        json.dumps({"incident_id": "inc-1", "reason": "FP1"}),
        json.dumps({"incident_id": "inc-2", "reason": "FP2"}),
    ]
    mock_redis.lrange = AsyncMock(return_value=stored_patterns)

    loop = FeedbackLoop(redis_client=mock_redis)
    patterns = await loop.get_fp_patterns()
    assert len(patterns) == 2
    assert patterns[0]["incident_id"] == "inc-1"
    assert patterns[1]["incident_id"] == "inc-2"


@pytest.mark.asyncio
async def test_severity_calibration_with_redis(mock_redis):
    """Severity calibration stored in Redis as JSON."""
    loop = FeedbackLoop(redis_client=mock_redis)
    feedback = AnalystFeedback(
        incident_id="inc-cal-001",
        analyst="analyst1",
        verdict=FeedbackVerdict.TRUE_POSITIVE,
        original_severity=70,
        adjusted_severity=85,
        severity_adjustment=15,
    )
    await loop.ingest_feedback(feedback)

    # lpush should have been called for both TP pattern and calibration
    assert mock_redis.lpush.call_count == 2
    # Check the calibration call
    calls = mock_redis.lpush.call_args_list
    calibration_call = calls[1]
    assert calibration_call[0][0] == "brain:severity_calibrations"
    stored = json.loads(calibration_call[0][1])
    assert stored["adjustment"] == 15
