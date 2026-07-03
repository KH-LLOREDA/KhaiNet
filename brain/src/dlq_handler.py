"""Dead Letter Queue handler for KhaiNet Brain.

Sends irrecuperable messages to the ``brain-dlq`` Kafka topic.
Each DLQ message includes the original message, error, timestamp, and component.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from confluent_kafka import Producer

from src.models import DLQMessage

log = structlog.get_logger()


class DLQHandler:
    """Sends failed messages to the Dead Letter Queue."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.topic = config.get("dlq_topic", "brain-dlq")
        self._producer: Producer | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stats = {"sent": 0}

    def _create_producer(self) -> Producer:
        return Producer(
            {
                "bootstrap.servers": self.config.get(
                    "bootstrap_servers", "localhost:9092"
                ),
            }
        )

    async def start(self) -> None:
        """Initialize the DLQ producer."""
        self._loop = asyncio.get_running_loop()
        self._producer = self._create_producer()
        log.info("dlq_handler_started", topic=self.topic)

    async def send(
        self,
        original_message: dict[str, Any],
        error: str,
        component: str,
        error_type: str = "",
        topic: str | None = None,
        partition: int | None = None,
        offset: int | None = None,
    ) -> None:
        """Send a message to the DLQ."""
        if self._producer is None:
            await self.start()
        assert self._producer is not None
        assert self._loop is not None

        dlq_msg = DLQMessage(
            original_message=original_message,
            error=error,
            error_type=error_type or type(error).__name__,
            component=component,
            topic=topic,
            partition=partition,
            offset=offset,
        )

        payload = json.dumps(dlq_msg.model_dump(mode="json"), default=str).encode(
            "utf-8"
        )

        def _produce() -> None:
            assert self._producer is not None
            self._producer.produce(self.topic, value=payload)
            self._producer.poll(0)

        await self._loop.run_in_executor(None, _produce)
        self._stats["sent"] += 1

        log.warning(
            "dlq_message_sent",
            error=error,
            component=component,
            original_topic=topic,
        )

    async def stop(self) -> None:
        """Flush and close the DLQ producer."""
        if self._producer and self._loop:
            await self._loop.run_in_executor(None, self._producer.flush, 10)
        log.info("dlq_handler_stopped", stats=self._stats)

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
