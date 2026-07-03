"""Tests for the Kafka consumer (AlertConsumer)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from src.consumer import AlertConsumer
from src.models import Alert


@pytest.mark.asyncio
async def test_consumer_creates_with_config(test_config):
    """Consumer initializes with config."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)
    assert consumer.config == test_config["kafka"]
    assert consumer.queue is queue


@pytest.mark.asyncio
async def test_consumer_process_valid_message(sample_alert_data, test_config):
    """Consumer validates and enqueues a valid alert message."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    msg = MagicMock()
    msg.value.return_value = json.dumps(sample_alert_data).encode("utf-8")
    msg.topic.return_value = "ml-scores"
    msg.partition.return_value = 0
    msg.offset.return_value = 0

    await consumer._process_message(msg)

    assert consumer.stats["received"] == 1
    assert consumer.stats["valid"] == 1
    assert not queue.empty()
    alert = await queue.get()
    assert isinstance(alert, Alert)
    assert alert.source == "ml-isolation-forest"


@pytest.mark.asyncio
async def test_consumer_process_invalid_message(test_config):
    """Consumer sends invalid messages to DLQ."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    dlq_called = False

    async def dlq_callback(*args, **kwargs):
        nonlocal dlq_called
        dlq_called = True

    consumer.set_dlq_callback(dlq_callback)

    msg = MagicMock()
    msg.value.return_value = b'{"invalid": "not an alert"}'
    msg.topic.return_value = "ml-scores"
    msg.partition.return_value = 0
    msg.offset.return_value = 0

    await consumer._process_message(msg)

    assert consumer.stats["received"] == 1
    assert consumer.stats["invalid"] == 1
    assert dlq_called
    assert queue.empty()


@pytest.mark.asyncio
async def test_consumer_process_malformed_json(test_config):
    """Consumer handles malformed JSON gracefully."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    msg = MagicMock()
    msg.value.return_value = b"not json at all"
    msg.topic.return_value = "ml-scores"
    msg.partition.return_value = 0
    msg.offset.return_value = 0

    await consumer._process_message(msg)

    assert consumer.stats["invalid"] == 1
    assert queue.empty()


# ---------------------------------------------------------------------------
# W8: Manual offset commit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consumer_commits_offset_after_valid_message(
    sample_alert_data, test_config
):
    """Consumer commits offset after processing a valid message."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    # Set up mock consumer and loop
    mock_kafka_consumer = MagicMock()
    mock_kafka_consumer.commit = MagicMock()
    consumer._consumer = mock_kafka_consumer
    consumer._loop = asyncio.get_running_loop()

    msg = MagicMock()
    msg.value.return_value = json.dumps(sample_alert_data).encode("utf-8")
    msg.topic.return_value = "ml-scores"
    msg.partition.return_value = 0
    msg.offset.return_value = 0

    await consumer._process_message(msg)

    # Offset should have been committed
    mock_kafka_consumer.commit.assert_called_once_with(msg)


@pytest.mark.asyncio
async def test_consumer_commits_offset_after_invalid_message(test_config):
    """Consumer commits offset even for invalid messages (to avoid reprocessing)."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    async def dlq_callback(*args, **kwargs):
        pass

    consumer.set_dlq_callback(dlq_callback)

    # Set up mock consumer and loop
    mock_kafka_consumer = MagicMock()
    mock_kafka_consumer.commit = MagicMock()
    consumer._consumer = mock_kafka_consumer
    consumer._loop = asyncio.get_running_loop()

    msg = MagicMock()
    msg.value.return_value = b'{"invalid": "not an alert"}'
    msg.topic.return_value = "ml-scores"
    msg.partition.return_value = 0
    msg.offset.return_value = 0

    await consumer._process_message(msg)

    # Offset should have been committed even for invalid message
    mock_kafka_consumer.commit.assert_called_once_with(msg)


@pytest.mark.asyncio
async def test_consumer_commit_offset_no_consumer(test_config):
    """_commit_offset is a no-op when consumer is not initialized."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    # Should not raise even without consumer/loop
    msg = MagicMock()
    await consumer._commit_offset(msg)
