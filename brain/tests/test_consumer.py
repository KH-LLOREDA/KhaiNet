"""Tests for the Kafka consumer (AlertConsumer)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

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
