"""Detection consumer: reads Zeek events from Kafka → detection/ → ml-scores.

Subscribes to zeek-conn, zeek-dns, zeek-http, zeek-ssl topics, accumulates
events in batches, passes them to the DetectionOrchestrator, and produces
the resulting model scores to the ml-scores topic.

Runs in a background thread. Uses auto_offset_reset='latest' to avoid
reprocessing historical data.

Can run standalone::

    python -m pipeline.src.detection_consumer
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import structlog
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from src.config import PipelineConfig
from src.cross_imports import (
    detection_context,
    generate_synthetic_zeek_logs,
)
from src.models import DetectionResult

log = structlog.get_logger()

# Topic mapping: Kafka topic → Zeek log type
TOPIC_TO_LOG_TYPE: dict[str, str] = {
    "zeek-conn": "conn",
    "zeek-dns": "dns",
    "zeek-http": "http",
    "zeek-ssl": "ssl",
}


class DetectionConsumer:
    """Consume Zeek events from Kafka, run detection, produce ML scores.

    Args:
        config: Pipeline configuration.
        orchestrator: Optional DetectionOrchestrator instance. If None,
            a new one is created and trained with synthetic data.
    """

    def __init__(
        self,
        config: PipelineConfig,
        orchestrator: Any | None = None,
    ) -> None:
        self.config = config
        self._orchestrator = orchestrator
        self._consumer: KafkaConsumer | None = None
        self._producer: KafkaProducer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

        # Event buffers (accumulated by type for batch processing)
        self._buffers: dict[str, list[Any]] = {
            "conn": [],
            "dns": [],
            "http": [],
            "ssl": [],
        }

        # Stats
        self._events_consumed = 0
        self._anomalies_detected = 0
        self._scores_produced = 0

        # Recent results (capped)
        self._recent_results: list[DetectionResult] = []
        self._max_recent = 100

        # Initialize orchestrator if not provided
        if self._orchestrator is None:
            self._init_and_train_orchestrator()

    def _init_and_train_orchestrator(self) -> None:
        """Create a new DetectionOrchestrator and train it with synthetic data."""
        log.info("initializing_detection_orchestrator")

        with detection_context():
            from src.orchestrator import DetectionOrchestrator as Orch

            self._orchestrator = Orch({"orchestrator": {"mock_mode": True}})

        # Generate synthetic training data
        conn_events = generate_synthetic_zeek_logs(
            "conn", n_events=500, anomaly_ratio=0.02, seed=42
        )
        dns_events = generate_synthetic_zeek_logs(
            "dns", n_events=200, anomaly_ratio=0.02, seed=43
        )
        http_events = generate_synthetic_zeek_logs(
            "http", n_events=100, anomaly_ratio=0.02, seed=44
        )
        ssl_events = generate_synthetic_zeek_logs(
            "ssl", n_events=50, anomaly_ratio=0.02, seed=45
        )

        # Train the orchestrator
        with detection_context():
            self._orchestrator.train_all(
                conn_events=conn_events,
                dns_events=dns_events,
                http_events=http_events,
                ssl_events=ssl_events,
            )

        log.info("orchestrator_trained", n_conn=len(conn_events))

    @property
    def consumer(self) -> KafkaConsumer:
        """Lazily create the KafkaConsumer."""
        if self._consumer is None:
            self._consumer = KafkaConsumer(
                *self.config.zeek_topics,
                bootstrap_servers=self.config.kafka_broker,
                client_id=self.config.kafka_client_id,
                group_id=self.config.consumer_group_detection,
                auto_offset_reset=self.config.auto_offset_reset,
                enable_auto_commit=True,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                consumer_timeout_ms=1000,
            )
        return self._consumer

    @property
    def producer(self) -> KafkaProducer:
        """Lazily create the KafkaProducer for ml-scores."""
        if self._producer is None:
            self._producer = KafkaProducer(
                bootstrap_servers=self.config.kafka_broker,
                client_id=self.config.kafka_client_id,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks=1,
                retries=3,
            )
        return self._producer

    def _parse_zeek_event(self, topic: str, payload: dict[str, Any]) -> Any | None:
        """Parse a Kafka message payload into a Zeek Pydantic model.

        Args:
            topic: Kafka topic name.
            payload: Message payload dict.

        Returns:
            A Zeek model instance (ZeekConn, ZeekDNS, etc.) or None on error.
        """
        log_type = TOPIC_TO_LOG_TYPE.get(topic)
        if log_type is None:
            return None

        try:
            with detection_context():
                if log_type == "conn":
                    from src.models import ZeekConn

                    return ZeekConn(**payload)
                elif log_type == "dns":
                    from src.models import ZeekDNS

                    return ZeekDNS(**payload)
                elif log_type == "http":
                    from src.models import ZeekHTTP

                    return ZeekHTTP(**payload)
                elif log_type == "ssl":
                    from src.models import ZeekSSL

                    return ZeekSSL(**payload)
        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.warning("zeek_parse_failed", topic=topic, error=str(exc))
            return None

    def _process_message(self, msg: Any) -> None:
        """Process a single Kafka message: parse, buffer, and maybe run detection.

        Args:
            msg: Kafka message with .topic, .value (dict), .timestamp.
        """
        topic = msg.topic
        payload = msg.value

        if not isinstance(payload, dict):
            return

        self._events_consumed += 1

        event = self._parse_zeek_event(topic, payload)
        if event is None:
            return

        log_type = TOPIC_TO_LOG_TYPE.get(topic, "")
        self._buffers[log_type].append(event)

        # Check if any buffer has enough events for a batch
        total_buffered = sum(len(b) for b in self._buffers.values())
        if total_buffered >= self.config.detection_batch_size:
            self._process_batch()

    def _process_batch(self) -> None:
        """Process the accumulated event buffer through the orchestrator."""
        conn_events = list(self._buffers["conn"])
        dns_events = list(self._buffers["dns"])
        http_events = list(self._buffers["http"])
        ssl_events = list(self._buffers["ssl"])

        # Clear buffers
        for key in self._buffers:
            self._buffers[key] = []

        if not any([conn_events, dns_events, http_events, ssl_events]):
            return

        log.info(
            "processing_batch",
            conn=len(conn_events),
            dns=len(dns_events),
            http=len(http_events),
            ssl=len(ssl_events),
        )

        try:
            # Run detection within detection_context for lazy imports
            with detection_context():
                model_results = self._orchestrator.detect(
                    conn_events=conn_events,
                    dns_events=dns_events,
                    http_events=http_events,
                    ssl_events=ssl_events,
                )
        except (Exception, RuntimeError, ValueError) as exc:  # noqa: BLE001
            log.error("detection_failed", error=str(exc))
            return

        if not model_results:
            return

        # Group results by event_id and produce to ml-scores
        results_by_event: dict[str, list[Any]] = defaultdict(list)
        for mr in model_results:
            results_by_event[mr.event_id].append(mr)

        for event_id, model_scores in results_by_event.items():
            scores_dict = {mr.model_name: mr.score for mr in model_scores}
            is_anomaly = any(mr.is_anomaly for mr in model_scores)
            fused_score = (
                sum(mr.score for mr in model_scores) / len(model_scores)
                if model_scores
                else 0.0
            )

            # Get src_ip/dst_ip from first result
            first = model_scores[0]
            result = DetectionResult(
                event_id=event_id,
                model_scores=scores_dict,
                fused_score=fused_score,
                is_anomaly=is_anomaly,
                threshold=first.threshold,
                timestamp=datetime.now(timezone.utc),
                src_ip=first.src_ip,
                dst_ip=first.dst_ip,
                details={
                    "model_count": len(model_scores),
                    "models": [mr.model_name for mr in model_scores],
                },
            )

            self._produce_score(result)

            if is_anomaly:
                self._anomalies_detected += 1

            # Store in recent results
            self._recent_results.append(result)
            if len(self._recent_results) > self._max_recent:
                self._recent_results.pop(0)

    def _produce_score(self, result: DetectionResult) -> None:
        """Produce a detection result to the ml-scores topic.

        Args:
            result: The DetectionResult to send.
        """
        payload = result.model_dump()
        # Ensure timestamp is ISO format
        if hasattr(payload.get("timestamp"), "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        try:
            self.producer.send("ml-scores", value=payload, key=result.src_ip or None)
            self._scores_produced += 1
        except KafkaError as exc:
            log.error("score_produce_failed", error=str(exc))

    def _run(self) -> None:
        """Main consumer loop (runs in background thread)."""
        log.info("detection_consumer_started")

        try:
            for msg in self.consumer:
                if not self._running:
                    break
                self._process_message(msg)
        except KafkaError as exc:
            log.error("consumer_error", error=str(exc))
        finally:
            # Process any remaining buffered events
            if any(len(b) > 0 for b in self._buffers.values()):
                self._process_batch()
            log.info("detection_consumer_stopped")

    def start(self) -> None:
        """Start the detection consumer in a background thread."""
        if self._running:
            log.warning("consumer_already_running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("detection_consumer_thread_started")

    def stop(self) -> None:
        """Stop the detection consumer."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def get_stats(self) -> dict[str, Any]:
        """Get consumer statistics.

        Returns:
            Dict with events consumed, anomalies detected, scores produced,
            and buffer sizes.
        """
        return {
            "events_consumed": self._events_consumed,
            "anomalies_detected": self._anomalies_detected,
            "scores_produced": self._scores_produced,
            "buffer_sizes": {k: len(v) for k, v in self._buffers.items()},
        }

    def get_recent_results(self, limit: int = 100) -> list[DetectionResult]:
        """Get recent detection results.

        Args:
            limit: Maximum number of results to return.

        Returns:
            List of recent DetectionResult objects (most recent last).
        """
        return self._recent_results[-limit:]

    def close(self) -> None:
        """Close consumer and producer connections."""
        self.stop()
        if self._consumer is not None:
            try:
                self._consumer.close()
            except KafkaError:
                pass
            self._consumer = None
        if self._producer is not None:
            try:
                self._producer.flush()
                self._producer.close()
            except KafkaError:
                pass
            self._producer = None


def main() -> None:
    """Run the detection consumer standalone."""
    import os
    import sys
    from pathlib import Path

    # Ensure pipeline/ root is in sys.path for `from src.xxx import`
    pipeline_root = str(Path(__file__).resolve().parents[1])
    if pipeline_root not in sys.path:
        sys.path.insert(0, pipeline_root)

    # Load config from YAML if specified, otherwise use defaults
    # Supports env var PIPELINE_CONFIG for Docker deployment
    config_path = os.environ.get("PIPELINE_CONFIG")
    if config_path and Path(config_path).exists():
        config = PipelineConfig.from_yaml(config_path)
        log.info("loaded_config_from_file", path=config_path)
    else:
        config = PipelineConfig()
        log.info("using_default_config")

    consumer = DetectionConsumer(config)

    log.info("starting_detection_consumer", broker=config.kafka_broker)
    consumer.start()

    try:
        while True:
            time.sleep(10)
            stats = consumer.get_stats()
            log.info("consumer_stats", **stats)
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
