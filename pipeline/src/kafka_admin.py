"""Kafka topic administration.

Wraps KafkaAdminClient and KafkaConsumer to provide topic management:
create, list, describe, delete topics, and check consumer group lag.

All operations handle errors gracefully (broker unavailable, topic already
exists, etc.) and log via structlog.
"""

from __future__ import annotations

from typing import Any

import structlog
from kafka import KafkaConsumer
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import KafkaError, TopicAlreadyExistsError

from src.config import PipelineConfig

log = structlog.get_logger()


class KafkaAdmin:
    """Manage Kafka topics and consumer groups.

    Args:
        config: Pipeline configuration with broker address and topic definitions.
    """

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self._admin: KafkaAdminClient | None = None

    @property
    def admin(self) -> KafkaAdminClient:
        """Lazily create and cache the KafkaAdminClient connection."""
        if self._admin is None:
            self._admin = KafkaAdminClient(
                bootstrap_servers=self.config.kafka_broker,
                client_id=self.config.kafka_client_id,
                request_timeout_ms=10000,
            )
        return self._admin

    def create_topics(self, topics: list[str]) -> dict[str, bool]:
        """Create Kafka topics if they don't exist.

        Args:
            topics: List of topic names to create.

        Returns:
            Dict mapping topic name → success (True if created or already exists).
        """
        results: dict[str, bool] = {}
        existing = set()

        try:
            existing = set(self.list_topics())
        except KafkaError as exc:
            log.warning("failed_to_list_existing_topics", error=str(exc))

        new_topics: list[NewTopic] = []
        for topic_name in topics:
            if topic_name in existing:
                results[topic_name] = True
                log.debug("topic_already_exists", topic=topic_name)
                continue

            topic_cfg = self.config.topics.get(topic_name, {})
            partitions = topic_cfg.get("partitions", 3)
            replication = topic_cfg.get("replication", 1)

            new_topics.append(
                NewTopic(
                    name=topic_name,
                    num_partitions=partitions,
                    replication_factor=replication,
                )
            )

        if new_topics:
            try:
                self.admin.create_topics(new_topics)
                for nt in new_topics:
                    results[nt.name] = True
                    log.info(
                        "topic_created",
                        topic=nt.name,
                        partitions=nt.num_partitions,
                        replication=nt.replication_factor,
                    )
            except TopicAlreadyExistsError:
                for nt in new_topics:
                    results[nt.name] = True
                    log.debug("topic_already_exists_race", topic=nt.name)
            except KafkaError as exc:
                log.error("failed_to_create_topics", error=str(exc))
                for nt in new_topics:
                    results[nt.name] = False

        return results

    def list_topics(self) -> list[str]:
        """List all topics in the Kafka cluster.

        Returns:
            List of topic names.
        """
        try:
            return list(self.admin.list_topics())
        except KafkaError as exc:
            log.error("failed_to_list_topics", error=str(exc))
            return []

    def describe_topic(self, name: str) -> dict[str, Any]:
        """Describe a topic: partitions, offsets, and basic stats.

        Args:
            name: Topic name.

        Returns:
            Dict with topic metadata: name, partitions, partition_details,
            total_offsets.
        """
        info: dict[str, Any] = {"name": name, "partitions": [], "total_offsets": 0}

        try:
            consumer = KafkaConsumer(
                name,
                bootstrap_servers=self.config.kafka_broker,
                client_id=self.config.kafka_client_id,
                enable_auto_commit=False,
                consumer_timeout_ms=5000,
            )
            partitions = consumer.partitions_for_topic(name) or set()
            info["partitions"] = sorted(partitions)

            partition_details: list[dict[str, Any]] = []
            total_offsets = 0

            for p in sorted(partitions):
                beginning = consumer.beginning_offsets([p])
                end = consumer.end_offsets([p])
                begin_off = beginning.get(p, 0)
                end_off = end.get(p, 0)
                offset_count = end_off - begin_off
                total_offsets += offset_count
                partition_details.append(
                    {
                        "partition": p,
                        "earliest_offset": begin_off,
                        "latest_offset": end_off,
                        "message_count": offset_count,
                    }
                )

            info["partition_details"] = partition_details
            info["total_offsets"] = total_offsets
            consumer.close()
        except KafkaError as exc:
            log.error("failed_to_describe_topic", topic=name, error=str(exc))
            info["error"] = str(exc)

        return info

    def delete_topic(self, name: str) -> bool:
        """Delete a Kafka topic.

        Args:
            name: Topic name to delete.

        Returns:
            True if deleted successfully, False otherwise.
        """
        try:
            self.admin.delete_topics([name])
            log.info("topic_deleted", topic=name)
            return True
        except KafkaError as exc:
            log.error("failed_to_delete_topic", topic=name, error=str(exc))
            return False

    def get_consumer_lag(self, group_id: str, topic: str) -> dict[str, Any]:
        """Get the consumer group lag for a specific topic.

        Args:
            group_id: Consumer group ID.
            topic: Topic name.

        Returns:
            Dict with per-partition lag and total lag.
        """
        result: dict[str, Any] = {
            "group_id": group_id,
            "topic": topic,
            "partition_lags": {},
            "total_lag": 0,
        }

        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=self.config.kafka_broker,
                client_id=self.config.kafka_client_id,
                group_id=group_id,
                enable_auto_commit=False,
                consumer_timeout_ms=5000,
            )

            partitions = consumer.partitions_for_topic(topic) or set()
            total_lag = 0

            for p in sorted(partitions):
                committed = consumer.committed(p) or 0
                end_off = consumer.end_offsets([p]).get(p, 0)
                lag = max(0, end_off - committed)
                total_lag += lag
                result["partition_lags"][str(p)] = {
                    "committed": committed,
                    "end_offset": end_off,
                    "lag": lag,
                }

            result["total_lag"] = total_lag
            consumer.close()
        except KafkaError as exc:
            log.error(
                "failed_to_get_consumer_lag",
                group_id=group_id,
                topic=topic,
                error=str(exc),
            )
            result["error"] = str(exc)

        return result

    def ensure_all_topics(self) -> dict[str, bool]:
        """Create all topics defined in the configuration if they don't exist.

        Returns:
            Dict mapping topic name → success.
        """
        all_topics = self.config.topic_names
        log.info("ensuring_topics", topics=all_topics)
        return self.create_topics(all_topics)

    def close(self) -> None:
        """Close the admin client connection."""
        if self._admin is not None:
            try:
                self._admin.close()
            except KafkaError:
                pass
            self._admin = None
