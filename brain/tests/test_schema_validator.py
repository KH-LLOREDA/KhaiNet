"""Tests for schema validation and hallucination detection."""

from __future__ import annotations

import pytest

from src.models import Alert, LLMOutput
from src.schema_validator import (
    SchemaValidationError,
    detect_hallucinations,
    extract_ips,
    validate_alert,
    validate_and_check_hallucinations,
    validate_llm_output,
)


def test_validate_alert_valid(sample_alert_data):
    """Valid alert passes validation."""
    alert = validate_alert(sample_alert_data)
    assert isinstance(alert, Alert)
    assert alert.source == "ml-isolation-forest"


def test_validate_alert_missing_required():
    """Alert missing required field fails validation."""
    with pytest.raises(SchemaValidationError):
        validate_alert({"alert_id": "test"})


def test_validate_alert_invalid_severity():
    """Alert with severity > 100 fails validation."""
    data = {
        "alert_id": "test-uuid",
        "timestamp": "2026-07-03T10:15:30Z",
        "source": "test",
        "source_type": "anomaly",
        "severity_raw": 150,  # > 100
        "confidence": 0.8,
        "src_ip": "abc",
        "dst_ip": "def",
        "protocol": "tcp",
        "event_type": "scan",
    }
    with pytest.raises(SchemaValidationError):
        validate_alert(data)


def test_validate_alert_invalid_confidence():
    """Alert with confidence > 1.0 fails validation."""
    data = {
        "alert_id": "test-uuid",
        "timestamp": "2026-07-03T10:15:30Z",
        "source": "test",
        "source_type": "anomaly",
        "severity_raw": 50,
        "confidence": 1.5,  # > 1.0
        "src_ip": "abc",
        "dst_ip": "def",
        "protocol": "tcp",
        "event_type": "scan",
    }
    with pytest.raises(SchemaValidationError):
        validate_alert(data)


def test_validate_llm_output_valid(valid_llm_output):
    """Valid LLM output passes validation."""
    result = validate_llm_output(valid_llm_output)
    assert isinstance(result, LLMOutput)
    assert result.title == valid_llm_output["title"]


def test_validate_llm_output_missing_field():
    """LLM output missing required field fails."""
    with pytest.raises(SchemaValidationError):
        validate_llm_output({"title": "test"})


def test_validate_llm_output_invalid_adjustment():
    """LLM output with severity_adjustment > 20 fails."""
    data = {
        "title": "Test",
        "description": "Test",
        "explanation": "Test",
        "correlation_reason": "Test",
        "false_positive_assessment": "Test",
        "severity_adjustment": 50,  # > 20
        "confidence": 0.8,
        "recommended_actions": [],
    }
    with pytest.raises(SchemaValidationError):
        validate_llm_output(data)


def test_extract_ips_real():
    """Extract real IPs from text."""
    text = "Connection from 192.168.1.1 to 10.0.0.1"
    ips = extract_ips(text)
    assert "192.168.1.1" in ips
    assert "10.0.0.1" in ips


def test_extract_ips_hashes():
    """Extract pseudonymized hashes from text."""
    text = "Source a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    ips = extract_ips(text)
    assert "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" in ips


def test_detect_hallucinations_clean(valid_llm_output):
    """No hallucinations when LLM output uses input IPs."""
    input_group = {
        "alerts": [
            {
                "src_ip": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
            }
        ],
        "entities": {
            "src_ips": [
                "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
            ]
        },
    }
    errors = detect_hallucinations(valid_llm_output, input_group)
    assert len(errors) == 0


def test_detect_hallucinations_found(hallucinated_llm_output):
    """Hallucination detected when LLM invents IPs."""
    input_group = {
        "alerts": [
            {
                "src_ip": "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1"
            }
        ],
        "entities": {
            "src_ips": [
                "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1"
            ]
        },
    }
    errors = detect_hallucinations(hallucinated_llm_output, input_group)
    assert len(errors) > 0
    assert "192.168.99.99" in errors[0] or "10.0.0.99" in errors[0]


def test_validate_and_check_hallucinations_raises(hallucinated_llm_output):
    """Full validation raises on hallucination."""
    input_group = {
        "alerts": [
            {
                "src_ip": "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1"
            }
        ],
        "entities": {
            "src_ips": [
                "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1"
            ]
        },
    }
    with pytest.raises(SchemaValidationError):
        validate_and_check_hallucinations(hallucinated_llm_output, input_group)


def test_validate_and_check_hallucinations_clean(valid_llm_output):
    """Full validation passes on clean output."""
    input_group = {
        "alerts": [
            {
                "src_ip": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
            }
        ],
        "entities": {
            "src_ips": [
                "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"
            ]
        },
    }
    result = validate_and_check_hallucinations(valid_llm_output, input_group)
    assert isinstance(result, LLMOutput)
