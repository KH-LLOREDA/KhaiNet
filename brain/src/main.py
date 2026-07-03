"""Main entry point for KhaiNet Brain.

Orchestrates the async pipeline:
1. Consumer reads alerts from Kafka → asyncio.Queue
2. Worker tasks process alerts: correlate → enrich → score → LLM → XAI → produce
3. Fallback graceful if LLM fails
4. DLQ for irrecuperable messages
5. Prometheus metrics server
6. Structured logging with structlog
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Any

import structlog
import yaml

from src.brain_client import BrainLLMClient, CircuitBreakerOpenError
from src.consumer import AlertConsumer
from src.correlator import Correlator
from src.dlq_handler import DLQHandler
from src.enricher import Enricher
from src.metrics import MetricsRecorder
from src.models import Alert, AlertGroup, Incident
from src.producer import IncidentProducer
from src.scorer import Scorer
from src.schema_validator import SchemaValidationError
from src.shuffle_client import ShuffleClient
from src.state_manager import SessionManager
from src.xai import XAIBuilder

log = structlog.get_logger()


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load configuration from YAML file and environment variable overrides."""
    if config_path is None:
        config_path = os.environ.get(
            "BRAIN_CONFIG_PATH",
            str(Path(__file__).parent.parent / "config" / "settings.yaml"),
        )

    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Environment variable overrides
    if kafka_servers := os.environ.get("KAFKA_BOOTSTRAP_SERVERS"):
        config["kafka"]["bootstrap_servers"] = kafka_servers
    if llm_url := os.environ.get("LLM_BASE_URL"):
        config["llm"]["base_url"] = llm_url
    if redis_url := os.environ.get("REDIS_URL"):
        config["redis"]["url"] = redis_url
    if misp_url := os.environ.get("MISP_URL"):
        config["enrichment"]["misp_url"] = misp_url
    if misp_key := os.environ.get("MISP_API_KEY"):
        config["enrichment"]["misp_api_key"] = misp_key
    if clickhouse_url := os.environ.get("CLICKHOUSE_URL"):
        config["enrichment"]["clickhouse_url"] = clickhouse_url
    if opensearch_url := os.environ.get("OPENSEARCH_URL"):
        config["enrichment"]["opensearch_url"] = opensearch_url
    if shuffle_url := os.environ.get("SHUFFLE_URL"):
        config["shuffle"]["url"] = shuffle_url
    if shuffle_key := os.environ.get("SHUFFLE_API_KEY"):
        config["shuffle"]["api_key"] = shuffle_key
    if log_level := os.environ.get("LOG_LEVEL"):
        config["logging"]["level"] = log_level

    return config


def setup_logging(config: dict[str, Any]) -> None:
    """Configure structlog for structured JSON logging."""
    level = config.get("logging", {}).get("level", "INFO")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
            if level == "DEBUG"
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, level, structlog.INFO)
        ),
        cache_logger_on_first_use=True,
    )


class BrainPipeline:
    """Main pipeline orchestrator.

    Wires together all components and runs the async event loop.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.queue: asyncio.Queue[Alert | None] = asyncio.Queue(maxsize=1000)
        self.metrics = MetricsRecorder()

        # Initialize components
        self.session_manager = SessionManager(
            redis_client=None,  # Will be set if Redis is available
            session_timeout_seconds=config.get("redis", {}).get(
                "session_timeout_seconds", 1800
            ),
        )
        self.correlator = Correlator(
            session_manager=self.session_manager,
            window_seconds=config.get("correlation", {}).get("window_seconds", 300),
            min_alerts_for_group=config.get("correlation", {}).get(
                "min_alerts_for_group", 2
            ),
        )
        self.enricher = Enricher(config.get("enrichment", {}))
        self.scorer = Scorer(config)
        self.brain_client = BrainLLMClient(config.get("llm", {}))
        self.xai_builder = XAIBuilder()
        self.shuffle_client = ShuffleClient(config.get("shuffle", {}))
        self.producer = IncidentProducer(config.get("kafka", {}))
        self.dlq_handler = DLQHandler(config.get("kafka", {}))

        self._running = False
        self._worker_tasks: list[asyncio.Task[None]] = []
        self._num_workers = config.get("workers", 3)

    async def setup(self) -> None:
        """Initialize all components."""
        # Start metrics server
        prom_port = self.config.get("prometheus", {}).get("port", 9090)
        try:
            self.metrics.start_metrics_server(prom_port)
        except OSError:
            log.warning("metrics_server_port_in_use", port=prom_port)

        # Set DLQ callback on consumer
        self.consumer = AlertConsumer(self.config.get("kafka", {}), self.queue)
        self.consumer.set_dlq_callback(self._dlq_callback)

        # Start producer and DLQ handler
        await self.producer.start()
        await self.dlq_handler.start()

    async def _dlq_callback(
        self,
        original_message: dict[str, Any],
        error: str,
        component: str,
        topic: str | None = None,
        partition: int | None = None,
        offset: int | None = None,
    ) -> None:
        """Callback for sending messages to DLQ."""
        await self.dlq_handler.send(
            original_message=original_message,
            error=error,
            component=component,
            topic=topic,
            partition=partition,
            offset=offset,
        )
        self.metrics.record_dlq_message()

    async def process_alert(self, alert: Alert) -> Incident | None:
        """Process a single alert through the full pipeline.

        Returns an Incident if one was produced, None otherwise.
        """
        start_time = asyncio.get_event_loop().time()
        self.metrics.record_alert_received(alert.source)

        try:
            # 1. Correlate
            groups = await self.correlator.process_alert(alert)

            # 2. Filter trivial groups pre-LLM
            groups = [g for g in groups if not self.correlator.should_filter_pre_llm(g)]

            if not groups:
                return None

            # Process each group (typically just one per alert)
            incident: Incident | None = None
            for group in groups:
                incident = await self._process_group(group)
                if incident:
                    break

            if incident:
                processing_time = asyncio.get_event_loop().time() - start_time
                self.metrics.record_processing_time(processing_time)
                self.metrics.record_incident_produced(
                    incident.severity_label
                    if isinstance(incident.severity_label, str)
                    else incident.severity_label.value
                )

            return incident

        except Exception as e:
            log.exception(
                "alert_processing_error", error=str(e), alert_id=alert.alert_id
            )
            await self._dlq_callback(
                alert.model_dump(mode="json"),
                str(e),
                "pipeline",
            )
            return None

    async def _process_group(self, group: AlertGroup) -> Incident | None:
        """Process a single alert group through enrichment, scoring, and LLM."""
        # 3. Enrich
        enrichment = await self.enricher.enrich(group)
        for failed in enrichment.failed_sources:
            self.metrics.record_enrichment_failure(failed)

        # 4. Score
        severity = self.scorer.calculate(group, enrichment)

        # 5. LLM with fallback
        try:
            group_dict = group.model_dump(mode="json")
            enrichment_dict = enrichment.model_dump(mode="json")
            llm_result = await self.brain_client.correlate(group_dict, enrichment_dict)

            latency_ms = llm_result.pop("_latency_ms", 0)
            self.metrics.record_llm_call("success", latency_ms / 1000)
            self.metrics.record_circuit_breaker_state(
                self.brain_client.circuit_breaker.state_value
            )

            # 6. Build incident with XAI
            incident = self.xai_builder.build_from_llm(
                group=group,
                enrichment=enrichment,
                severity=severity,
                llm_output=llm_result,
                llm_model=self.brain_client.model,
                llm_latency_ms=latency_ms,
            )
            self.metrics.record_xai_available()
            return incident

        except (CircuitBreakerOpenError, SchemaValidationError) as e:
            # Fallback: scoring without XAI
            self.metrics.record_llm_call("failure", 0)
            self.metrics.record_circuit_breaker_state(
                self.brain_client.circuit_breaker.state_value
            )
            self.metrics.record_xai_fallback()
            log.warning("llm_fallback_activated", reason=str(e), entity=group.entity)

            incident = self.xai_builder.build_fallback(
                group=group,
                enrichment=enrichment,
                severity=severity,
                confidence=0.5,
            )
            return incident

        except Exception as e:
            # Unexpected error — fallback
            self.metrics.record_llm_call("failure", 0)
            self.metrics.record_xai_fallback()
            log.exception("llm_unexpected_error", error=str(e))

            incident = self.xai_builder.build_fallback(
                group=group,
                enrichment=enrichment,
                severity=severity,
                confidence=0.3,
            )
            return incident

    async def _worker(self, worker_id: int) -> None:
        """Worker task that processes alerts from the queue."""
        log.info("worker_started", worker_id=worker_id)
        while self._running:
            try:
                alert = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                if alert is None:
                    break
                incident = await self.process_alert(alert)
                if incident:
                    # 7. Produce to Kafka
                    await self.producer.produce(incident)
                    # 8. Send to Shuffle
                    await self.shuffle_client.send_incident(incident)
                self.queue.task_done()
            except TimeoutError:
                continue
            except Exception as e:
                log.exception("worker_error", worker_id=worker_id, error=str(e))
        log.info("worker_stopped", worker_id=worker_id)

    async def run(self) -> None:
        """Start the pipeline: consumer + workers."""
        await self.setup()
        self._running = True

        # Start consumer
        await self.consumer.start()

        # Start worker tasks
        self._worker_tasks = [
            asyncio.create_task(self._worker(i)) for i in range(self._num_workers)
        ]

        log.info("brain_pipeline_started", workers=self._num_workers)

        # Wait for shutdown signal
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            log.info("shutdown_signal_received")
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except NotImplementedError:
                pass

        await stop_event.wait()
        await self.shutdown()

    async def shutdown(self) -> None:
        """Gracefully shutdown all components."""
        log.info("brain_pipeline_shutting_down")
        self._running = False

        # Signal workers to stop
        for _ in self._worker_tasks:
            await self.queue.put(None)

        # Wait for workers to finish
        if self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)

        # Stop consumer
        await self.consumer.stop()

        # Flush and close producer
        await self.producer.stop()

        # Close DLQ handler
        await self.dlq_handler.stop()

    async def process_single_alert(self, alert: Alert) -> Incident | None:
        """Process a single alert without starting the full pipeline.

        Useful for testing and integration.
        """
        return await self.process_alert(alert)


async def main() -> None:
    """Main entry point."""
    config = load_config()
    setup_logging(config)
    pipeline = BrainPipeline(config)
    await pipeline.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("interrupted_by_user")
        sys.exit(0)
