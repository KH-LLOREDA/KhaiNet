"""Pipeline configuration.

Loads from YAML or can be constructed programmatically. Contains all
settings for Kafka broker, topics, sensor simulation, and consumer groups.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

# Default topic definitions (8 topics)
DEFAULT_TOPICS: dict[str, dict[str, int]] = {
    "zeek-conn": {"partitions": 3, "replication": 1},
    "zeek-dns": {"partitions": 3, "replication": 1},
    "zeek-http": {"partitions": 3, "replication": 1},
    "zeek-ssl": {"partitions": 3, "replication": 1},
    "suricata-alerts": {"partitions": 3, "replication": 1},
    "wazuh-events": {"partitions": 3, "replication": 1},
    "ml-scores": {"partitions": 3, "replication": 1},
    "brain-incidents": {"partitions": 3, "replication": 1},
}

# Default anomaly types for sensor simulation
DEFAULT_ANOMALY_TYPES: list[str] = [
    "port_scan",
    "data_exfil",
    "c2_beacon",
    "dns_tunneling",
]


class PipelineConfig(BaseModel):
    """Configuration for the KhaiNet pipeline.

    Attributes:
        kafka_broker: Kafka broker address (host:port).
        kafka_client_id: Client ID for Kafka connections.
        topics: Topic definitions with partitions and replication factor.
        sensor_rate: Events per second for the sensor simulator.
        anomaly_ratio: Fraction of events that are anomalies (0.0-1.0).
        anomaly_types: Types of anomalies to inject.
        consumer_group_detection: Consumer group for detection consumer.
        consumer_group_tuning: Consumer group for tuning consumer.
        detection_batch_size: Batch size for detection processing.
        auto_offset_reset: Offset reset policy (latest/earliest).
        temporal_window_seconds: Temporal alignment window for tuning.
    """

    model_config = ConfigDict(extra="ignore")

    kafka_broker: str = "172.26.10.98:9092"
    kafka_client_id: str = "khainet-pipeline"
    topics: dict[str, dict[str, int]] = Field(
        default_factory=lambda: dict(DEFAULT_TOPICS)
    )
    sensor_rate: int = 10
    anomaly_ratio: float = 0.05
    anomaly_types: list[str] = Field(
        default_factory=lambda: list(DEFAULT_ANOMALY_TYPES)
    )
    consumer_group_detection: str = "detection-consumer"
    consumer_group_tuning: str = "tuning-consumer"
    detection_batch_size: int = 20
    auto_offset_reset: str = "latest"
    temporal_window_seconds: int = 60

    @property
    def topic_names(self) -> list[str]:
        """Return the list of all topic names."""
        return list(self.topics.keys())

    @property
    def zeek_topics(self) -> list[str]:
        """Return only the Zeek-related topic names."""
        return ["zeek-conn", "zeek-dns", "zeek-http", "zeek-ssl"]

    @property
    def alert_topics(self) -> list[str]:
        """Return the alert source topic names."""
        return ["suricata-alerts", "wazuh-events"]

    @classmethod
    def from_yaml(cls, path: str | Path) -> PipelineConfig:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            A PipelineConfig instance populated from the YAML data.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}

        # Flatten the YAML structure into our flat config
        kafka_cfg = data.get("kafka", {})
        topics_cfg = data.get("topics", {})
        sensor_cfg = data.get("sensor", {})
        detection_cfg = data.get("detection", {})
        tuning_cfg = data.get("tuning", {})

        return cls(
            kafka_broker=kafka_cfg.get("broker", "172.26.10.98:9092"),
            kafka_client_id=kafka_cfg.get("client_id", "khainet-pipeline"),
            topics=topics_cfg if topics_cfg else dict(DEFAULT_TOPICS),
            sensor_rate=sensor_cfg.get("rate", 10),
            anomaly_ratio=sensor_cfg.get("anomaly_ratio", 0.05),
            anomaly_types=sensor_cfg.get("anomaly_types", list(DEFAULT_ANOMALY_TYPES)),
            consumer_group_detection=detection_cfg.get(
                "consumer_group", "detection-consumer"
            ),
            detection_batch_size=detection_cfg.get("batch_size", 20),
            auto_offset_reset=detection_cfg.get("auto_offset_reset", "latest"),
            consumer_group_tuning=tuning_cfg.get("consumer_group", "tuning-consumer"),
            temporal_window_seconds=tuning_cfg.get("temporal_window_seconds", 60),
        )
