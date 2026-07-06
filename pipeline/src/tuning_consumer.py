"""Tuning consumer: reads alerts/scores from Kafka → tuning/ labels → incidents.

Subscribes to suricata-alerts, wazuh-events, and ml-scores topics.
Processes Suricata/Wazuh alerts into weak labels via tuning/ label sources,
combines them via the WeakSupervisor, and produces consensus incidents to
the brain-incidents topic when there's enough confidence.

Also reads ml-scores for temporal alignment and runs active learning to
select uncertain events for analyst review.

Runs in a background thread. Uses auto_offset_reset='latest'.

Can run standalone::

    python -m pipeline.src.tuning_consumer
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from src.config import PipelineConfig
from src.cross_imports import (
    create_active_learning_selector,
    create_tuning_labelers,
    create_weak_supervisor,
    tuning_context,
)
from src.models import TuningLabel

log = structlog.get_logger()

# Topics this consumer subscribes to
TUNING_TOPICS = ["suricata-alerts", "wazuh-events", "ml-scores"]


class TuningConsumer:
    """Consume alerts and scores from Kafka, generate labels, produce incidents.

    Args:
        config: Pipeline configuration.
    """

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self._consumer: KafkaConsumer | None = None
        self._producer: KafkaProducer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

        # Labelers and supervisor (lazily initialized)
        self._labelers: dict[str, Any] | None = None
        self._supervisor: Any | None = None
        self._active_learner: Any | None = None

        # Score buffer for temporal alignment: event_id → score data
        self._score_buffer: dict[str, dict[str, Any]] = {}
        self._max_buffer_size = 1000

        # Pending weak labels (collected before combining)
        self._pending_labels: list[Any] = []

        # Stats
        self._labels_by_source: dict[str, int] = defaultdict(int)
        self._active_learning_queries = 0
        self._incidents_produced = 0
        self._events_consumed = 0

    def _ensure_components(self) -> None:
        """Lazily initialize labelers, supervisor, and active learner."""
        if self._labelers is None:
            self._labelers = create_tuning_labelers()
        if self._supervisor is None:
            sources = list(self._labelers.values())
            self._supervisor = create_weak_supervisor(sources=sources)
        if self._active_learner is None:
            self._active_learner = create_active_learning_selector()

    @property
    def consumer(self) -> KafkaConsumer:
        """Lazily create the KafkaConsumer."""
        if self._consumer is None:
            self._consumer = KafkaConsumer(
                *TUNING_TOPICS,
                bootstrap_servers=self.config.kafka_broker,
                client_id=self.config.kafka_client_id,
                group_id=self.config.consumer_group_tuning,
                auto_offset_reset=self.config.auto_offset_reset,
                enable_auto_commit=True,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                consumer_timeout_ms=1000,
            )
        return self._consumer

    @property
    def producer(self) -> KafkaProducer:
        """Lazily create the KafkaProducer for brain-incidents."""
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

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    def _process_suricata(self, msg: Any) -> None:
        """Process a Suricata alert: convert to weak label via SuricataLabeler.

        Args:
            msg: Kafka message with Suricata alert payload.
        """
        self._ensure_components()
        payload = msg.value
        if not isinstance(payload, dict):
            return

        try:
            alert = self._parse_suricata_alert(payload)
            if alert is None:
                return

            # Generate weak labels from the alert (labelers already loaded)
            labeler = self._labelers["suricata"]
            weak_labels = labeler.generate_labels([alert])

            for wl in weak_labels:
                self._pending_labels.append(wl)
                self._labels_by_source["suricata"] += 1

            log.debug(
                "suricata_processed",
                n_labels=len(weak_labels),
            )
        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.warning("suricata_process_failed", error=str(exc))

    def _parse_suricata_alert(self, payload: dict[str, Any]) -> Any | None:
        """Parse a Suricata alert payload into a SuricataAlert model.

        Args:
            payload: Raw alert payload dict.

        Returns:
            SuricataAlert instance or None on error.
        """
        try:
            with tuning_context():
                from src.models import SuricataAlert

                return SuricataAlert(**payload)
        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.warning("suricata_parse_failed", error=str(exc))
            return None

    def _process_wazuh(self, msg: Any) -> None:
        """Process a Wazuh event: convert to weak label via WazuhLabeler.

        Args:
            msg: Kafka message with Wazuh event payload.
        """
        self._ensure_components()
        payload = msg.value
        if not isinstance(payload, dict):
            return

        try:
            alert = self._parse_wazuh_alert(payload)
            if alert is None:
                return

            # Generate weak labels from the alert (labelers already loaded)
            labeler = self._labelers["wazuh"]
            weak_labels = labeler.generate_labels([alert])

            for wl in weak_labels:
                self._pending_labels.append(wl)
                self._labels_by_source["wazuh"] += 1

            log.debug(
                "wazuh_processed",
                n_labels=len(weak_labels),
            )
        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.warning("wazuh_process_failed", error=str(exc))

    def _parse_wazuh_alert(self, payload: dict[str, Any]) -> Any | None:
        """Parse a Wazuh alert payload into a WazuhAlert model.

        Args:
            payload: Raw alert payload dict.

        Returns:
            WazuhAlert instance or None on error.
        """
        try:
            with tuning_context():
                from src.models import WazuhAlert

                return WazuhAlert(**payload)
        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.warning("wazuh_parse_failed", error=str(exc))
            return None

    def _process_ml_scores(self, msg: Any) -> None:
        """Process an ml-scores message: store in buffer for temporal alignment.

        Args:
            msg: Kafka message with detection result payload.
        """
        payload = msg.value
        if not isinstance(payload, dict):
            return

        event_id = payload.get("event_id", str(uuid4()))
        self._score_buffer[event_id] = {
            "event_id": event_id,
            "model_scores": payload.get("model_scores", {}),
            "fused_score": payload.get("fused_score", 0.0),
            "is_anomaly": payload.get("is_anomaly", False),
            "timestamp": payload.get("timestamp"),
            "src_ip": payload.get("src_ip", ""),
            "dst_ip": payload.get("dst_ip", ""),
        }

        # Trim buffer if too large
        if len(self._score_buffer) > self._max_buffer_size:
            # Remove oldest entries (approximate: remove first 100)
            keys = list(self._score_buffer.keys())[:100]
            for k in keys:
                del self._score_buffer[k]

        # Try to combine pending labels if we have enough
        if len(self._pending_labels) >= 5:
            self._combine_and_produce()

    def _combine_and_produce(self) -> None:
        """Combine pending weak labels via the WeakSupervisor and produce incidents."""
        if not self._pending_labels:
            return

        self._ensure_components()

        try:
            with tuning_context():
                consensus_labels = self._supervisor.combine_labels(self._pending_labels)
        except (Exception, RuntimeError) as exc:  # noqa: BLE001
            log.error("label_combination_failed", error=str(exc))
            self._pending_labels.clear()
            return

        # Produce incidents for positive consensus labels
        for cl in consensus_labels:
            if cl.label and cl.confidence > 0.5:
                self._produce_incident(cl)

        # Clear pending labels
        n_combined = len(consensus_labels)
        self._pending_labels.clear()

        log.info(
            "labels_combined",
            n_input=n_combined,
            n_positive=sum(1 for c in consensus_labels if c.label),
            n_incidents=self._incidents_produced,
        )

    def _produce_incident(self, consensus_label: Any) -> None:
        """Produce a brain incident to the brain-incidents topic.

        Args:
            consensus_label: A ConsensusLabel with label=True.
        """
        # Look up score from buffer for temporal alignment
        score_data = self._score_buffer.get(consensus_label.event_id, {})

        incident: dict[str, Any] = {
            "incident_id": str(uuid4()),
            "event_id": consensus_label.event_id,
            "timestamp": consensus_label.timestamp.isoformat()
            if hasattr(consensus_label.timestamp, "isoformat")
            else str(consensus_label.timestamp),
            "src_ip": consensus_label.src_ip,
            "dst_ip": consensus_label.dst_ip,
            "label": consensus_label.label,
            "confidence": consensus_label.confidence,
            "contributing_sources": consensus_label.contributing_sources,
            "vote_breakdown": consensus_label.vote_breakdown,
            "votes_positive": consensus_label.votes_positive,
            "votes_negative": consensus_label.votes_negative,
            "mitre_attack_id": consensus_label.mitre_attack_id,
            "event_type": consensus_label.event_type,
            "model_scores": score_data.get("model_scores", {}),
            "fused_score": score_data.get("fused_score", 0.0),
        }

        try:
            self.producer.send(
                "brain-incidents",
                value=incident,
                key=consensus_label.src_ip or None,
            )
            self._incidents_produced += 1
            log.info(
                "incident_produced",
                event_id=consensus_label.event_id,
                confidence=consensus_label.confidence,
                sources=consensus_label.contributing_sources,
            )
        except KafkaError as exc:
            log.error("incident_produce_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Analyst feedback
    # ------------------------------------------------------------------

    def submit_analyst_feedback(
        self,
        event_id: str,
        label: bool,
        comment: str = "",
    ) -> TuningLabel:
        """Submit analyst feedback for an event.

        Creates an AnalystFeedback, converts it to a weak label via the
        AnalystLabeler, and adds it to the pending labels for combination.

        Args:
            event_id: The event being labeled.
            label: True=confirmed anomaly, False=confirmed normal.
            comment: Optional analyst comment.

        Returns:
            A TuningLabel representing the analyst feedback.
        """
        self._ensure_components()

        # Look up event data from score buffer
        score_data = self._score_buffer.get(event_id, {})
        src_ip = score_data.get("src_ip", "")
        dst_ip = score_data.get("dst_ip", "")

        now = datetime.now(timezone.utc)

        try:
            feedback = self._create_analyst_feedback(
                event_id=event_id,
                label=label,
                comment=comment,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=now,
            )
            if feedback is None:
                raise RuntimeError("Failed to create AnalystFeedback")

            # Generate weak label from feedback (labeler already loaded)
            labeler = self._labelers["analyst"]
            weak_labels = labeler.generate_labels([feedback])

            for wl in weak_labels:
                self._pending_labels.append(wl)
                self._labels_by_source["analyst"] += 1

            # Try to combine immediately since analyst labels are high-priority
            self._combine_and_produce()

        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.error("analyst_feedback_failed", error=str(exc))

        tuning_label = TuningLabel(
            event_id=event_id,
            source="analyst",
            label=label,
            confidence=1.0,
            timestamp=now,
            event_type="analyst_confirmed",
        )

        log.info(
            "analyst_feedback_submitted",
            event_id=event_id,
            label=label,
            comment=comment,
        )
        return tuning_label

    def _create_analyst_feedback(
        self,
        event_id: str,
        label: bool,
        comment: str,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> Any | None:
        """Create an AnalystFeedback model instance.

        Args:
            event_id: The event being labeled.
            label: True=anomaly, False=normal.
            comment: Analyst comment.
            src_ip: Source IP.
            dst_ip: Destination IP.
            timestamp: Feedback timestamp.

        Returns:
            AnalystFeedback instance or None on error.
        """
        try:
            with tuning_context():
                from src.models import AnalystFeedback

                return AnalystFeedback(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    label=label,
                    analyst_id="pipeline-analyst",
                    event_id=event_id,
                    notes=comment,
                )
        except (Exception, TypeError, ValueError) as exc:  # noqa: BLE001
            log.warning("analyst_feedback_create_failed", error=str(exc))
            return None

    # ------------------------------------------------------------------
    # Active learning
    # ------------------------------------------------------------------

    def _run_active_learning(self) -> None:
        """Select uncertain events for analyst review using active learning."""
        if not self._score_buffer:
            return

        self._ensure_components()

        try:
            with tuning_context():
                from src.models import ModelScore

                # Convert score buffer to ModelScore objects
                model_scores: list[ModelScore] = []
                for event_id, data in list(self._score_buffer.items()):
                    ts = data.get("timestamp")
                    if isinstance(ts, str):
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    elif ts is None:
                        ts = datetime.now(timezone.utc)

                    for model_name, score in data.get("model_scores", {}).items():
                        model_scores.append(
                            ModelScore(
                                event_id=event_id,
                                timestamp=ts,
                                src_ip=data.get("src_ip", ""),
                                dst_ip=data.get("dst_ip", ""),
                                model_name=model_name,
                                score=float(score),
                            )
                        )

                if not model_scores:
                    return

                # Select batch for review
                thresholds = {"isolation_forest": 0.7, "autoencoder": 0.7, "hmm": 0.7}
                batch = self._active_learner.select_batch(
                    events=model_scores,
                    thresholds=thresholds,
                )

                self._active_learning_queries += len(batch.queries)
                log.info(
                    "active_learning_batch",
                    n_queries=len(batch.queries),
                    strategy=batch.strategy,
                )
        except (Exception, RuntimeError) as exc:  # noqa: BLE001
            log.warning("active_learning_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _process_message(self, msg: Any) -> None:
        """Route a message to the appropriate processor based on topic.

        Args:
            msg: Kafka message.
        """
        self._events_consumed += 1
        topic = msg.topic

        if topic == "suricata-alerts":
            self._process_suricata(msg)
        elif topic == "wazuh-events":
            self._process_wazuh(msg)
        elif topic == "ml-scores":
            self._process_ml_scores(msg)

    def _run(self) -> None:
        """Main consumer loop (runs in background thread)."""
        log.info("tuning_consumer_started")
        last_al_time = time.time()

        try:
            for msg in self.consumer:
                if not self._running:
                    break
                self._process_message(msg)

                # Run active learning periodically (every 30 seconds)
                now = time.time()
                if now - last_al_time > 30:
                    self._run_active_learning()
                    last_al_time = now

        except KafkaError as exc:
            log.error("consumer_error", error=str(exc))
        finally:
            # Combine any remaining labels
            if self._pending_labels:
                self._combine_and_produce()
            log.info("tuning_consumer_stopped")

    def start(self) -> None:
        """Start the tuning consumer in a background thread."""
        if self._running:
            log.warning("consumer_already_running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("tuning_consumer_thread_started")

    def stop(self) -> None:
        """Stop the tuning consumer."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def get_stats(self) -> dict[str, Any]:
        """Get consumer statistics.

        Returns:
            Dict with labels by source, active learning queries,
            incidents produced, events consumed, and buffer sizes.
        """
        return {
            "labels_by_source": dict(self._labels_by_source),
            "active_learning_queries": self._active_learning_queries,
            "incidents_produced": self._incidents_produced,
            "events_consumed": self._events_consumed,
            "score_buffer_size": len(self._score_buffer),
            "pending_labels": len(self._pending_labels),
        }

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
    """Run the tuning consumer standalone."""
    import sys
    from pathlib import Path

    # Ensure pipeline/ root is in sys.path for `from src.xxx import`
    pipeline_root = str(Path(__file__).resolve().parents[1])
    if pipeline_root not in sys.path:
        sys.path.insert(0, pipeline_root)

    config = PipelineConfig()
    consumer = TuningConsumer(config)

    log.info("starting_tuning_consumer", broker=config.kafka_broker)
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
