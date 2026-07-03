"""Async Kafka consumer for KhaiNet Brain.

Consumes from 3 input topics (ml-scores, suricata-alerts, wazuh-events) and
pushes validated alerts into an internal ``asyncio.Queue`` to decouple
consumption from the inference pipeline.

Uses ``confluent-kafka`` with a polling loop run in a thread executor to avoid
blocking the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from confluent_kafka import Consumer, KafkaError, KafkaException

from src.models import Alert
from src.schema_validator import SchemaValidationError, validate_alert

log = structlog.get_logger()


class AlertConsumer:
    """Async wrapper around confluent-kafka Consumer.

    Polls Kafka in a background thread and puts validated ``Alert`` objects
    onto an ``asyncio.Queue`` for downstream processing.
    """

    def __init__(
        self,
        config: dict[str, Any],
        output_queue: asyncio.Queue[Alert | None],
    ) -> None:
        self.config = config
        self.queue = output_queue
        self._consumer: Consumer | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._dlq_callback: Any = None
        self._stats = {
            "received": 0,
            "valid": 0,
            "invalid": 0,
        }

    def _create_consumer(self) -> Consumer:
        """Create the underlying confluent-kafka Consumer."""
        return Consumer(
            {
                "bootstrap.servers": self.config.get(
                    "bootstrap_servers", "localhost:9092"
                ),
                "group.id": self.config.get("group_id", "brain-consumer"),
                "auto.offset.reset": self.config.get("auto_offset_reset", "latest"),
                "enable.auto.commit": self.config.get("enable_auto_commit", False),
            }
        )

    async def start(self) -> None:
        """Start consuming from Kafka."""
        self._loop = asyncio.get_running_loop()
        consumer = self._create_consumer()
        self._consumer = consumer
        topics = self.config.get("input_topics", [])
        consumer.subscribe(topics)
        self._running = True
        log.info("consumer_started", topics=topics)
        # Run the poll loop in a thread to avoid blocking asyncio
        asyncio.create_task(self._poll_loop())

    async def _poll_loop(self) -> None:
        """Background task that polls Kafka and feeds the queue."""
        assert self._consumer is not None
        assert self._loop is not None
        consumer = self._consumer
        loop = self._loop
        poll_timeout = self.config.get("poll_timeout", 1.0)
        while self._running:
            try:
                # Run the blocking poll in an executor
                msg = await loop.run_in_executor(None, consumer.poll, poll_timeout)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    log.error("kafka_error", error=str(msg.error()))
                    continue

                await self._process_message(msg)
            except KafkaException as e:
                log.error("kafka_exception", error=str(e))
            except (RuntimeError, OSError, ValueError, TypeError) as e:
                log.exception("consumer_poll_error", error=str(e))

    async def _process_message(self, msg: Any) -> None:
        """Parse, validate and enqueue a Kafka message."""
        self._stats["received"] += 1
        try:
            raw = msg.value()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            data = json.loads(raw)
            alert = validate_alert(data)
            self._stats["valid"] += 1
            await self.queue.put(alert)
        except (json.JSONDecodeError, SchemaValidationError) as e:
            self._stats["invalid"] += 1
            log.warning(
                "alert_validation_failed",
                error=str(e),
                topic=msg.topic(),
                partition=msg.partition(),
                offset=msg.offset(),
            )
            # Send to DLQ via the queue as a special marker
            await self._send_to_dlq(msg, str(e))

    async def _send_to_dlq(self, msg: Any, error: str) -> None:
        """Send invalid message to DLQ. Override or hook for DLQ handler."""
        # The DLQ handler is injected by main.py via a callback
        if hasattr(self, "_dlq_callback") and self._dlq_callback:
            raw = msg.value()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            try:
                original = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                original = {"raw": raw}
            await self._dlq_callback(
                original,
                error,
                "consumer",
                topic=msg.topic(),
                partition=msg.partition(),
                offset=msg.offset(),
            )

    def set_dlq_callback(self, callback: Any) -> None:
        """Set the DLQ callback for invalid messages."""
        self._dlq_callback = callback

    async def stop(self) -> None:
        """Stop consuming and close the consumer."""
        self._running = False
        if self._consumer and self._loop:
            await self._loop.run_in_executor(None, self._consumer.close)
        log.info("consumer_stopped", stats=self._stats)

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
