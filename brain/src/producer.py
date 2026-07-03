"""Kafka producer for KhaiNet Brain.

Produces incidents to the ``brain-incidents`` topic.
Uses confluent-kafka Producer with async delivery callbacks.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from confluent_kafka import Producer

from src.models import Incident

log = structlog.get_logger()


class IncidentProducer:
    """Async wrapper around confluent-kafka Producer."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.topic = config.get("output_topic", "brain-incidents")
        self._producer: Producer | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stats = {"produced": 0, "failed": 0}

    def _create_producer(self) -> Producer:
        return Producer(
            {
                "bootstrap.servers": self.config.get(
                    "bootstrap_servers", "localhost:9092"
                ),
            }
        )

    def _delivery_report(self, err: Any, msg: Any) -> None:
        """Callback for Kafka delivery confirmation."""
        if err is not None:
            log.error("kafka_delivery_failed", error=str(err))
            self._stats["failed"] += 1
        else:
            self._stats["produced"] += 1

    async def start(self) -> None:
        """Initialize the producer."""
        self._loop = asyncio.get_running_loop()
        self._producer = self._create_producer()
        log.info("producer_started", topic=self.topic)

    async def produce(self, incident: Incident) -> None:
        """Produce an incident to Kafka."""
        if self._producer is None:
            await self.start()
        assert self._producer is not None
        assert self._loop is not None

        payload = json.dumps(incident.model_dump_json_safe(), default=str).encode(
            "utf-8"
        )
        key = incident.incident_id.encode("utf-8")

        def _produce() -> None:
            assert self._producer is not None
            self._producer.produce(
                topic=self.topic,
                key=key,
                value=payload,
                callback=self._delivery_report,
            )
            self._producer.poll(0)

        await self._loop.run_in_executor(None, _produce)

        log.info(
            "incident_produced",
            incident_id=incident.incident_id,
            severity=incident.severity,
            alert_count=len(incident.alerts),
            xai_available=incident.xai_available,
        )

    async def flush(self) -> None:
        """Flush pending messages."""
        if self._producer and self._loop:
            await self._loop.run_in_executor(None, self._producer.flush, 10)

    async def stop(self) -> None:
        """Flush and close the producer."""
        await self.flush()
        log.info("producer_stopped", stats=self._stats)

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
