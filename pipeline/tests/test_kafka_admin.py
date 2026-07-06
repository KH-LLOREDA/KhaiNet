"""Tests for KafkaAdmin — all use mocks, no real Kafka broker required."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.kafka_admin import KafkaAdmin


@pytest.fixture
def config() -> PipelineConfig:
    return PipelineConfig()


@pytest.fixture
def admin(config: PipelineConfig) -> KafkaAdmin:
    return KafkaAdmin(config)


class TestKafkaAdminInit:
    """Test KafkaAdmin initialization."""

    def test_init_with_config(self, config: PipelineConfig) -> None:
        admin = KafkaAdmin(config)
        assert admin.config is config
        assert admin._admin is None

    def test_admin_lazy_creation(self, admin: KafkaAdmin) -> None:
        with patch("src.kafka_admin.KafkaAdminClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            result = admin.admin
            assert result is mock_instance
            mock_client.assert_called_once()

    def test_admin_cached(self, admin: KafkaAdmin) -> None:
        with patch("src.kafka_admin.KafkaAdminClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            _ = admin.admin
            _ = admin.admin
            mock_client.assert_called_once()


class TestCreateTopics:
    """Test topic creation."""

    def test_create_topics_all_new(self, admin: KafkaAdmin) -> None:
        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.return_value = []
        mock_admin_client.create_topics.return_value = None
        admin._admin = mock_admin_client

        results = admin.create_topics(["zeek-conn", "zeek-dns"])

        assert results["zeek-conn"] is True
        assert results["zeek-dns"] is True
        mock_admin_client.create_topics.assert_called_once()

    def test_create_topics_already_exists(self, admin: KafkaAdmin) -> None:
        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.return_value = ["zeek-conn"]
        admin._admin = mock_admin_client

        results = admin.create_topics(["zeek-conn"])

        assert results["zeek-conn"] is True
        mock_admin_client.create_topics.assert_not_called()

    def test_create_topics_mixed(self, admin: KafkaAdmin) -> None:
        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.return_value = ["zeek-conn"]
        mock_admin_client.create_topics.return_value = None
        admin._admin = mock_admin_client

        results = admin.create_topics(["zeek-conn", "zeek-dns"])

        assert results["zeek-conn"] is True
        assert results["zeek-dns"] is True

    def test_create_topics_failure(self, admin: KafkaAdmin) -> None:
        from kafka.errors import KafkaError

        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.return_value = []
        mock_admin_client.create_topics.side_effect = KafkaError("broker down")
        admin._admin = mock_admin_client

        results = admin.create_topics(["zeek-conn"])

        assert results["zeek-conn"] is False


class TestListTopics:
    """Test topic listing."""

    def test_list_topics_success(self, admin: KafkaAdmin) -> None:
        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.return_value = ["topic1", "topic2"]
        admin._admin = mock_admin_client

        result = admin.list_topics()

        assert "topic1" in result
        assert "topic2" in result

    def test_list_topics_failure(self, admin: KafkaAdmin) -> None:
        from kafka.errors import KafkaError

        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.side_effect = KafkaError("broker down")
        admin._admin = mock_admin_client

        result = admin.list_topics()

        assert result == []


class TestDescribeTopic:
    """Test topic description."""

    def test_describe_topic_success(self, admin: KafkaAdmin) -> None:
        with patch("src.kafka_admin.KafkaConsumer") as mock_consumer_cls:
            mock_consumer = MagicMock()
            mock_consumer_cls.return_value = mock_consumer
            mock_consumer.partitions_for_topic.return_value = {0, 1}
            mock_consumer.beginning_offsets.return_value = {0: 0, 1: 0}
            mock_consumer.end_offsets.return_value = {0: 100, 1: 50}

            result = admin.describe_topic("zeek-conn")

            assert result["name"] == "zeek-conn"
            assert result["partitions"] == [0, 1]
            assert result["total_offsets"] == 150

    def test_describe_topic_failure(self, admin: KafkaAdmin) -> None:
        from kafka.errors import KafkaError

        with patch("src.kafka_admin.KafkaConsumer") as mock_consumer_cls:
            mock_consumer_cls.side_effect = KafkaError("broker down")

            result = admin.describe_topic("zeek-conn")

            assert result["name"] == "zeek-conn"
            assert "error" in result


class TestDeleteTopic:
    """Test topic deletion."""

    def test_delete_topic_success(self, admin: KafkaAdmin) -> None:
        mock_admin_client = MagicMock()
        mock_admin_client.delete_topics.return_value = None
        admin._admin = mock_admin_client

        result = admin.delete_topic("zeek-conn")

        assert result is True

    def test_delete_topic_failure(self, admin: KafkaAdmin) -> None:
        from kafka.errors import KafkaError

        mock_admin_client = MagicMock()
        mock_admin_client.delete_topics.side_effect = KafkaError("broker down")
        admin._admin = mock_admin_client

        result = admin.delete_topic("zeek-conn")

        assert result is False


class TestConsumerLag:
    """Test consumer lag retrieval."""

    def test_get_consumer_lag_success(self, admin: KafkaAdmin) -> None:
        with patch("src.kafka_admin.KafkaConsumer") as mock_consumer_cls:
            mock_consumer = MagicMock()
            mock_consumer_cls.return_value = mock_consumer
            mock_consumer.partitions_for_topic.return_value = {0, 1}
            mock_consumer.committed.return_value = 50
            mock_consumer.end_offsets.return_value = {0: 100, 1: 80}

            result = admin.get_consumer_lag("test-group", "zeek-conn")

            assert result["group_id"] == "test-group"
            assert result["topic"] == "zeek-conn"
            assert result["total_lag"] == 80  # (100-50) + (80-50)

    def test_get_consumer_lag_failure(self, admin: KafkaAdmin) -> None:
        from kafka.errors import KafkaError

        with patch("src.kafka_admin.KafkaConsumer") as mock_consumer_cls:
            mock_consumer_cls.side_effect = KafkaError("broker down")

            result = admin.get_consumer_lag("test-group", "zeek-conn")

            assert "error" in result


class TestEnsureAllTopics:
    """Test ensure_all_topics."""

    def test_ensure_all_topics(self, admin: KafkaAdmin) -> None:
        with patch.object(admin, "create_topics") as mock_create:
            mock_create.return_value = {t: True for t in admin.config.topic_names}

            results = admin.ensure_all_topics()

            assert len(results) == 8
            assert all(results.values())
            mock_create.assert_called_once()

    def test_ensure_all_topics_creates_all_8(self, admin: KafkaAdmin) -> None:
        mock_admin_client = MagicMock()
        mock_admin_client.list_topics.return_value = []
        mock_admin_client.create_topics.return_value = None
        admin._admin = mock_admin_client

        results = admin.ensure_all_topics()

        assert len(results) == 8
        for topic_name in admin.config.topic_names:
            assert topic_name in results
