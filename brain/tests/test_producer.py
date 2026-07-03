"""Tests for the Kafka incident producer."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.models import Incident, severity_to_label
from src.producer import IncidentProducer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_incident(sample_alert):
    """Create a sample incident for producer tests."""
    return Incident(
        severity=75,
        severity_label=severity_to_label(75),
        confidence=0.85,
        title="Test incident for producer",
        description="Test description",
        correlation_reason="Test correlation",
        false_positive_assessment="Not a FP",
        alerts=[sample_alert],
        xai_available=True,
        llm_model="test-model",
        llm_latency_ms=500,
    )


# ---------------------------------------------------------------------------
# Producer tests
# ---------------------------------------------------------------------------


def test_producer_init():
    """Producer initializes with config."""
    producer = IncidentProducer(
        {"bootstrap_servers": "localhost:9092", "output_topic": "brain-incidents"}
    )
    assert producer.topic == "brain-incidents"
    assert producer._producer is None


def test_producer_default_topic():
    """Producer uses default topic if not specified."""
    producer = IncidentProducer({})
    assert producer.topic == "brain-incidents"


@pytest.mark.asyncio
async def test_producer_start():
    """start() creates the underlying confluent-kafka Producer."""
    producer = IncidentProducer(
        {"bootstrap_servers": "localhost:9092", "output_topic": "brain-incidents"}
    )

    mock_kafka_producer = MagicMock()
    with patch("src.producer.Producer", return_value=mock_kafka_producer):
        await producer.start()

    assert producer._producer is mock_kafka_producer
    assert producer._loop is not None


@pytest.mark.asyncio
async def test_producer_produce(sample_incident):
    """produce() sends the incident to Kafka."""
    producer = IncidentProducer(
        {"bootstrap_servers": "localhost:9092", "output_topic": "brain-incidents"}
    )

    mock_kafka_producer = MagicMock()
    with patch("src.producer.Producer", return_value=mock_kafka_producer):
        await producer.start()
        await producer.produce(sample_incident)

    # Verify produce was called with correct topic and key
    mock_kafka_producer.produce.assert_called_once()
    call_kwargs = mock_kafka_producer.produce.call_args
    assert call_kwargs[1]["topic"] == "brain-incidents"
    assert call_kwargs[1]["key"] == sample_incident.incident_id.encode("utf-8")

    # Verify the payload is valid JSON
    payload = call_kwargs[1]["value"]
    data = json.loads(payload.decode("utf-8"))
    assert data["incident_id"] == sample_incident.incident_id
    assert data["severity"] == 75


@pytest.mark.asyncio
async def test_producer_auto_start(sample_incident):
    """produce() auto-starts the producer if not started."""
    producer = IncidentProducer(
        {"bootstrap_servers": "localhost:9092", "output_topic": "brain-incidents"}
    )

    mock_kafka_producer = MagicMock()
    with patch("src.producer.Producer", return_value=mock_kafka_producer):
        await producer.produce(sample_incident)

    # Producer should have been auto-started
    assert producer._producer is mock_kafka_producer


@pytest.mark.asyncio
async def test_producer_flush():
    """flush() calls flush on the underlying producer."""
    producer = IncidentProducer(
        {"bootstrap_servers": "localhost:9092", "output_topic": "brain-incidents"}
    )

    mock_kafka_producer = MagicMock()
    with patch("src.producer.Producer", return_value=mock_kafka_producer):
        await producer.start()
        await producer.flush()

    mock_kafka_producer.flush.assert_called_once()


@pytest.mark.asyncio
async def test_producer_stop():
    """stop() flushes and logs stats."""
    producer = IncidentProducer(
        {"bootstrap_servers": "localhost:9092", "output_topic": "brain-incidents"}
    )

    mock_kafka_producer = MagicMock()
    with patch("src.producer.Producer", return_value=mock_kafka_producer):
        await producer.start()
        await producer.stop()

    mock_kafka_producer.flush.assert_called_once()


@pytest.mark.asyncio
async def test_producer_delivery_report_success():
    """_delivery_report increments produced count on success."""
    producer = IncidentProducer({})
    producer._delivery_report(None, MagicMock())
    assert producer.stats["produced"] == 1
    assert producer.stats["failed"] == 0


@pytest.mark.asyncio
async def test_producer_delivery_report_failure():
    """_delivery_report increments failed count on error."""
    producer = IncidentProducer({})
    producer._delivery_report(Exception("delivery failed"), None)
    assert producer.stats["failed"] == 1
    assert producer.stats["produced"] == 0


@pytest.mark.asyncio
async def test_producer_stats_property():
    """stats property returns a copy of the stats dict."""
    producer = IncidentProducer({})
    stats = producer.stats
    assert "produced" in stats
    assert "failed" in stats
    # Modifying the returned dict should not affect the internal state
    stats["produced"] = 999
    assert producer.stats["produced"] == 0
