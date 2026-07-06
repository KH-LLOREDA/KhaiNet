"""Sensor simulator: produces synthetic Zeek/Suricata/Wazuh events to Kafka.

Generates realistic network sensor data using detection/synthetic_data.py
for Zeek events and custom generators for Suricata/Wazuh alerts. Events
are serialized as JSON UTF-8 and sent to the appropriate Kafka topics.

Anomaly injection is configurable: a fraction of events are marked as
anomalies (port_scan, data_exfil, c2_beacon, dns_tunneling).

Can run standalone::

    python -m pipeline.src.sensor_simulator
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog
from kafka import KafkaProducer
from kafka.errors import KafkaError

from src.config import PipelineConfig
from src.cross_imports import generate_synthetic_zeek_logs
from src.models import SensorEvent

log = structlog.get_logger()

# Salt for IP pseudonymization (matches detection/synthetic_data.py)
_SALT = "khainet-salt"

# Suricata alert signatures by anomaly type
SURICATA_SIGNATURES: dict[str, dict[str, Any]] = {
    "port_scan": {
        "signature": "ET SCAN Nmap TCP SYN scan",
        "category": "Network Scan",
        "severity": 2,
        "mitre_id": "T1046",
    },
    "data_exfil": {
        "signature": "ET POLICY outbound DNS query with high entropy (data exfil)",
        "category": "Data Exfiltration",
        "severity": 1,
        "mitre_id": "T1041",
    },
    "c2_beacon": {
        "signature": "ET MALWARE C2 Beacon interval detected",
        "category": "Trojan Activity",
        "severity": 1,
        "mitre_id": "T1071",
    },
    "dns_tunneling": {
        "signature": "ET DNS Tunneling detected via long TXT query",
        "category": "DNS Tunneling",
        "severity": 1,
        "mitre_id": "T1071",
    },
}

# Wazuh alert templates by type
WAZUH_TEMPLATES: dict[str, dict[str, Any]] = {
    "port_scan": {
        "rule_id": "5710",
        "rule_level": 10,
        "rule_description": "Multiple authentication failures (possible scan)",
        "rule_groups": ["authentication", "attacks"],
        "event_type": "auth",
    },
    "data_exfil": {
        "rule_id": "550",
        "rule_level": 12,
        "rule_description": "Large file modification detected (possible exfil)",
        "rule_groups": ["syscheck"],
        "event_type": "syscheck",
    },
    "c2_beacon": {
        "rule_id": "503",
        "rule_level": 11,
        "rule_description": "C2 beaconing pattern detected by log analysis",
        "rule_groups": ["malware"],
        "event_type": "malware",
    },
    "dns_tunneling": {
        "rule_id": "40801",
        "rule_level": 9,
        "rule_description": "DNS tunneling indicator detected",
        "rule_groups": ["dns", "malware"],
        "event_type": "dns",
    },
}

# Distribution of event types in produce_batch
EVENT_DISTRIBUTION: list[tuple[str, float]] = [
    ("zeek_conn", 0.35),
    ("zeek_dns", 0.20),
    ("zeek_http", 0.15),
    ("zeek_ssl", 0.10),
    ("suricata_alert", 0.12),
    ("wazuh_event", 0.08),
]


def _pseudonymize_ip(seed: str) -> str:
    """Pseudonymize an IP-like string into a SHA-256 hash."""
    return hashlib.sha256(f"{_SALT}:{seed}".encode()).hexdigest()


def _random_ip(rng: random.Random, prefix: str = "host") -> str:
    """Generate a random pseudonymized IP hash."""
    return _pseudonymize_ip(f"{prefix}-{rng.randint(0, 10_000_000)}")


def _make_uid(rng: random.Random) -> str:
    """Generate a Zeek-style UID (hex string)."""
    return "".join(rng.choice("0123456789abcdef") for _ in range(16))


class SensorSimulator:
    """Produce synthetic sensor events to Kafka topics.

    Generates Zeek connection/DNS/HTTP/SSL events using detection/synthetic_data.py,
    and Suricata/Wazuh alerts with custom realistic generators. Events are
    serialized as JSON UTF-8 and sent to the appropriate Kafka topics.

    Args:
        config: Pipeline configuration.
        producer: Optional KafkaProducer instance. If None, one is created
            lazily on first produce call.
    """

    def __init__(
        self,
        config: PipelineConfig,
        producer: KafkaProducer | None = None,
    ) -> None:
        self.config = config
        self._producer = producer
        self._rng = random.Random()
        self._running = False
        self._seed_counter = 0

        # Stats
        self._stats: dict[str, int] = {
            "zeek_conn": 0,
            "zeek_dns": 0,
            "zeek_http": 0,
            "zeek_ssl": 0,
            "suricata_alert": 0,
            "wazuh_event": 0,
        }
        self._anomaly_count = 0
        self._total_produced = 0

    @property
    def producer(self) -> KafkaProducer:
        """Lazily create and cache the KafkaProducer."""
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

    def _next_seed(self) -> int:
        """Get an incrementing seed for reproducible generation."""
        self._seed_counter += 1
        return self._seed_counter

    def _should_inject_anomaly(self) -> bool:
        """Decide whether to inject an anomaly based on anomaly_ratio."""
        return self._rng.random() < self.config.anomaly_ratio

    def _pick_anomaly_type(self) -> str:
        """Pick a random anomaly type from the configured list."""
        return self._rng.choice(self.config.anomaly_types)

    def _send(
        self, topic: str, payload: dict[str, Any], key: str | None = None
    ) -> bool:
        """Send a message to Kafka.

        Args:
            topic: Kafka topic name.
            payload: Message payload (will be JSON-serialized).
            key: Optional partition key.

        Returns:
            True if sent successfully, False on error.
        """
        try:
            self.producer.send(topic, value=payload, key=key)
            return True
        except KafkaError as exc:
            log.error("kafka_send_failed", topic=topic, error=str(exc))
            return False

    # ------------------------------------------------------------------
    # Zeek event producers
    # ------------------------------------------------------------------

    def produce_zeek_conn(self) -> SensorEvent:
        """Generate a Zeek conn event and send it to the ``zeek-conn`` topic.

        Returns:
            The SensorEvent that was produced.
        """
        is_anomaly = self._should_inject_anomaly()
        anomaly_ratio = 1.0 if is_anomaly else 0.0
        anomaly_type = self._pick_anomaly_type() if is_anomaly else None

        events = generate_synthetic_zeek_logs(
            "conn", n_events=1, anomaly_ratio=anomaly_ratio, seed=self._next_seed()
        )
        if not events:
            return SensorEvent(
                event_type="zeek_conn",
                source="zeek",
                data={},
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
            )

        event = events[0]
        payload = event.model_dump()
        # Ensure timestamp is ISO format for JSON
        if "timestamp" in payload and hasattr(payload["timestamp"], "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        self._send("zeek-conn", payload, key=event.src_ip)
        self._stats["zeek_conn"] += 1
        self._total_produced += 1
        if is_anomaly:
            self._anomaly_count += 1

        return SensorEvent(
            event_type="zeek_conn",
            source="zeek",
            data=payload,
            timestamp=event.timestamp,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )

    def produce_zeek_dns(self) -> SensorEvent:
        """Generate a Zeek DNS event and send it to the ``zeek-dns`` topic.

        Returns:
            The SensorEvent that was produced.
        """
        is_anomaly = self._should_inject_anomaly()
        anomaly_ratio = 1.0 if is_anomaly else 0.0
        anomaly_type = "dns_tunneling" if is_anomaly else None

        events = generate_synthetic_zeek_logs(
            "dns", n_events=1, anomaly_ratio=anomaly_ratio, seed=self._next_seed()
        )
        if not events:
            return SensorEvent(
                event_type="zeek_dns",
                source="zeek",
                data={},
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
            )

        event = events[0]
        payload = event.model_dump()
        if "timestamp" in payload and hasattr(payload["timestamp"], "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        self._send("zeek-dns", payload, key=event.src_ip)
        self._stats["zeek_dns"] += 1
        self._total_produced += 1
        if is_anomaly:
            self._anomaly_count += 1

        return SensorEvent(
            event_type="zeek_dns",
            source="zeek",
            data=payload,
            timestamp=event.timestamp,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )

    def produce_zeek_http(self) -> SensorEvent:
        """Generate a Zeek HTTP event and send it to the ``zeek-http`` topic.

        Returns:
            The SensorEvent that was produced.
        """
        is_anomaly = self._should_inject_anomaly()
        anomaly_ratio = 1.0 if is_anomaly else 0.0
        anomaly_type = self._pick_anomaly_type() if is_anomaly else None

        events = generate_synthetic_zeek_logs(
            "http", n_events=1, anomaly_ratio=anomaly_ratio, seed=self._next_seed()
        )
        if not events:
            return SensorEvent(
                event_type="zeek_http",
                source="zeek",
                data={},
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
            )

        event = events[0]
        payload = event.model_dump()
        if "timestamp" in payload and hasattr(payload["timestamp"], "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        self._send("zeek-http", payload, key=event.src_ip)
        self._stats["zeek_http"] += 1
        self._total_produced += 1
        if is_anomaly:
            self._anomaly_count += 1

        return SensorEvent(
            event_type="zeek_http",
            source="zeek",
            data=payload,
            timestamp=event.timestamp,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )

    def produce_zeek_ssl(self) -> SensorEvent:
        """Generate a Zeek SSL event and send it to the ``zeek-ssl`` topic.

        Returns:
            The SensorEvent that was produced.
        """
        is_anomaly = self._should_inject_anomaly()
        anomaly_ratio = 1.0 if is_anomaly else 0.0
        anomaly_type = "c2_beacon" if is_anomaly else None

        events = generate_synthetic_zeek_logs(
            "ssl", n_events=1, anomaly_ratio=anomaly_ratio, seed=self._next_seed()
        )
        if not events:
            return SensorEvent(
                event_type="zeek_ssl",
                source="zeek",
                data={},
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
            )

        event = events[0]
        payload = event.model_dump()
        if "timestamp" in payload and hasattr(payload["timestamp"], "isoformat"):
            payload["timestamp"] = payload["timestamp"].isoformat()

        self._send("zeek-ssl", payload, key=event.src_ip)
        self._stats["zeek_ssl"] += 1
        self._total_produced += 1
        if is_anomaly:
            self._anomaly_count += 1

        return SensorEvent(
            event_type="zeek_ssl",
            source="zeek",
            data=payload,
            timestamp=event.timestamp,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )

    # ------------------------------------------------------------------
    # Suricata / Wazuh alert producers
    # ------------------------------------------------------------------

    def produce_suricata_alert(self) -> SensorEvent:
        """Generate a synthetic Suricata alert and send it to ``suricata-alerts``.

        Returns:
            The SensorEvent that was produced.
        """
        is_anomaly = True  # Suricata alerts are always anomalies
        anomaly_type = self._pick_anomaly_type()
        sig_info = SURICATA_SIGNATURES.get(
            anomaly_type, SURICATA_SIGNATURES["port_scan"]
        )

        now = datetime.now(timezone.utc)
        src_ip = _random_ip(self._rng, "suricata-src")
        dst_ip = _random_ip(self._rng, "suricata-dst")

        payload: dict[str, Any] = {
            "timestamp": now.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": self._rng.randint(1024, 65535),
            "dst_port": self._rng.choice([22, 80, 443, 445, 8080]),
            "protocol": "tcp",
            "alert_signature": sig_info["signature"],
            "alert_category": sig_info["category"],
            "alert_severity": sig_info["severity"],
            "rule_id": str(self._rng.randint(2000000, 2999999)),
            "mitre_attack_id": sig_info["mitre_id"],
            "flow_id": str(uuid4()),
        }

        self._send("suricata-alerts", payload, key=src_ip)
        self._stats["suricata_alert"] += 1
        self._total_produced += 1
        self._anomaly_count += 1

        return SensorEvent(
            event_type="suricata_alert",
            source="suricata",
            data=payload,
            timestamp=now,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )

    def produce_wazuh_event(self) -> SensorEvent:
        """Generate a synthetic Wazuh event and send it to ``wazuh-events``.

        Returns:
            The SensorEvent that was produced.
        """
        is_anomaly = True  # Wazuh alerts are always anomalies
        anomaly_type = self._pick_anomaly_type()
        template = WAZUH_TEMPLATES.get(anomaly_type, WAZUH_TEMPLATES["port_scan"])

        now = datetime.now(timezone.utc)
        src_ip = _random_ip(self._rng, "wazuh-src")
        dst_ip = _random_ip(self._rng, "wazuh-dst")

        payload: dict[str, Any] = {
            "timestamp": now.isoformat(),
            "agent_id": str(self._rng.randint(1, 100)),
            "agent_name": f"agent-{self._rng.randint(1, 50)}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "rule_id": template["rule_id"],
            "rule_level": template["rule_level"],
            "rule_description": template["rule_description"],
            "rule_groups": template["rule_groups"],
            "event_type": template["event_type"],
            "full_log": f"[{now.isoformat()}] {template['rule_description']}",
        }

        self._send("wazuh-events", payload, key=src_ip)
        self._stats["wazuh_event"] += 1
        self._total_produced += 1
        self._anomaly_count += 1

        return SensorEvent(
            event_type="wazuh_event",
            source="wazuh",
            data=payload,
            timestamp=now,
            is_anomaly=is_anomaly,
            anomaly_type=anomaly_type,
        )

    # ------------------------------------------------------------------
    # Batch and continuous production
    # ------------------------------------------------------------------

    def produce_batch(self, n_events: int) -> list[SensorEvent]:
        """Produce a batch of mixed events.

        Events are randomly distributed across types according to
        ``EVENT_DISTRIBUTION``. Anomaly ratio is respected per-event.

        Args:
            n_events: Number of events to produce.

        Returns:
            List of SensorEvents that were produced.
        """
        results: list[SensorEvent] = []

        for _ in range(n_events):
            r = self._rng.random()
            cumulative = 0.0
            chosen_type = EVENT_DISTRIBUTION[0][0]

            for event_type, prob in EVENT_DISTRIBUTION:
                cumulative += prob
                if r <= cumulative:
                    chosen_type = event_type
                    break

            if chosen_type == "zeek_conn":
                results.append(self.produce_zeek_conn())
            elif chosen_type == "zeek_dns":
                results.append(self.produce_zeek_dns())
            elif chosen_type == "zeek_http":
                results.append(self.produce_zeek_http())
            elif chosen_type == "zeek_ssl":
                results.append(self.produce_zeek_ssl())
            elif chosen_type == "suricata_alert":
                results.append(self.produce_suricata_alert())
            elif chosen_type == "wazuh_event":
                results.append(self.produce_wazuh_event())

        log.info(
            "batch_produced",
            n_events=len(results),
            total_produced=self._total_produced,
        )
        return results

    def start(
        self,
        duration_seconds: int | None = None,
        rate: int | None = None,
    ) -> None:
        """Start producing events continuously.

        Args:
            duration_seconds: How long to produce events. If None, runs
                indefinitely until stop() is called.
            rate: Events per second. If None, uses config.sensor_rate.
        """
        events_per_second = rate or self.config.sensor_rate
        interval = 1.0 / events_per_second if events_per_second > 0 else 1.0

        self._running = True
        start_time = time.time()
        log.info(
            "simulator_started",
            rate=events_per_second,
            duration=duration_seconds,
        )

        try:
            while self._running:
                if duration_seconds is not None:
                    elapsed = time.time() - start_time
                    if elapsed >= duration_seconds:
                        break

                self.produce_batch(1)
                time.sleep(interval)
        except KeyboardInterrupt:
            log.info("simulator_interrupted")
        finally:
            self._running = False
            log.info(
                "simulator_stopped",
                total_produced=self._total_produced,
                anomaly_count=self._anomaly_count,
            )

    def stop(self) -> None:
        """Stop the simulator."""
        self._running = False

    def get_stats(self) -> dict[str, Any]:
        """Get production statistics.

        Returns:
            Dict with events by type, total produced, anomaly count,
            and anomaly ratio.
        """
        return {
            "events_by_type": dict(self._stats),
            "total_produced": self._total_produced,
            "anomaly_count": self._anomaly_count,
            "anomaly_ratio": (
                self._anomaly_count / self._total_produced
                if self._total_produced > 0
                else 0.0
            ),
        }

    def close(self) -> None:
        """Close the Kafka producer if we created it."""
        if self._producer is not None:
            try:
                self._producer.flush()
                self._producer.close()
            except KafkaError:
                pass


def main() -> None:
    """Run the sensor simulator standalone."""
    import sys
    from pathlib import Path

    # Ensure pipeline/ root is in sys.path for `from src.xxx import`
    pipeline_root = str(Path(__file__).resolve().parents[1])
    if pipeline_root not in sys.path:
        sys.path.insert(0, pipeline_root)

    config = PipelineConfig()
    simulator = SensorSimulator(config)

    log.info("starting_sensor_simulator", broker=config.kafka_broker)
    try:
        simulator.start(duration_seconds=60)
    except KeyboardInterrupt:
        pass
    finally:
        simulator.close()
        stats = simulator.get_stats()
        log.info("final_stats", **stats)


if __name__ == "__main__":
    main()
