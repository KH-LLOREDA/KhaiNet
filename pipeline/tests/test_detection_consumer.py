"""Tests for DetectionConsumer — uses mock consumer and orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.detection_consumer import DetectionConsumer
from src.models import DetectionResult


@pytest.fixture
def config() -> PipelineConfig:
    return PipelineConfig(detection_batch_size=5)


@pytest.fixture
def mock_orchestrator() -> MagicMock:
    orch = MagicMock()
    mock_result = MagicMock()
    mock_result.model_name = "isolation_forest"
    mock_result.event_id = "test-event-1"
    mock_result.score = 0.8
    mock_result.is_anomaly = True
    mock_result.threshold = 0.7
    mock_result.src_ip = "hash_src"
    mock_result.dst_ip = "hash_dst"
    mock_result.timestamp = datetime.now(timezone.utc)
    mock_result.details = {}
    orch.detect.return_value = [mock_result]
    return orch


@pytest.fixture
def consumer(config: PipelineConfig, mock_orchestrator: MagicMock) -> DetectionConsumer:
    return DetectionConsumer(config, orchestrator=mock_orchestrator)


class TestDetectionConsumerInit:
    """Test initialization."""

    def test_init_with_orchestrator(
        self, config: PipelineConfig, mock_orchestrator: MagicMock
    ) -> None:
        dc = DetectionConsumer(config, orchestrator=mock_orchestrator)
        assert dc._orchestrator is mock_orchestrator
        assert dc._events_consumed == 0

    def test_init_without_orchestrator_trains(self, config: PipelineConfig) -> None:
        """Test that init creates and trains orchestrator when none is provided."""
        with patch.object(
            DetectionConsumer, "_init_and_train_orchestrator"
        ) as mock_train:
            dc = DetectionConsumer(config)

            # _init_and_train_orchestrator should have been called
            mock_train.assert_called_once()
            # The orchestrator won't be set (since we mocked the method),
            # but we verify the training path was invoked
            assert dc._events_consumed == 0


class TestProcessMessage:
    """Test message processing."""

    def test_process_message_zeek_conn(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        msg = MagicMock()
        msg.topic = "zeek-conn"
        msg.value = {"timestamp": "2026-07-01T00:00:00+00:00", "src_ip": "h1"}

        # Mock _parse_zeek_event to return a mock event
        mock_event = MagicMock()
        with patch.object(consumer, "_parse_zeek_event", return_value=mock_event):
            consumer._process_message(msg)

        assert consumer._events_consumed == 1
        assert len(consumer._buffers["conn"]) == 1

    def test_process_message_invalid_payload_skipped(
        self, consumer: DetectionConsumer
    ) -> None:
        msg = MagicMock()
        msg.topic = "zeek-conn"
        msg.value = "not a dict"

        consumer._process_message(msg)
        assert consumer._events_consumed == 0

    def test_process_message_parse_failure(self, consumer: DetectionConsumer) -> None:
        msg = MagicMock()
        msg.topic = "zeek-conn"
        msg.value = {"bad": "data"}

        with patch.object(consumer, "_parse_zeek_event", return_value=None):
            consumer._process_message(msg)

        # events_consumed is incremented before parse
        assert consumer._events_consumed == 1
        assert len(consumer._buffers["conn"]) == 0


class TestProcessBatch:
    """Test batch processing."""

    def test_process_batch_runs_detection(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        consumer._buffers["conn"] = [MagicMock(), MagicMock()]
        consumer._buffers["dns"] = [MagicMock()]

        with patch("src.detection_consumer.detection_context"):
            consumer._process_batch()

        mock_orchestrator.detect.assert_called_once()
        assert consumer._scores_produced > 0

    def test_process_batch_empty_buffers_noop(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        consumer._process_batch()
        mock_orchestrator.detect.assert_not_called()

    def test_process_batch_produces_to_ml_scores(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        consumer._buffers["conn"] = [MagicMock()]

        with (
            patch("src.detection_consumer.detection_context"),
            patch.object(consumer, "_produce_score") as mock_produce,
        ):
            consumer._process_batch()

            mock_produce.assert_called()

    def test_process_batch_stores_recent_results(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        consumer._buffers["conn"] = [MagicMock()]

        with patch("src.detection_consumer.detection_context"):
            consumer._process_batch()

        assert len(consumer._recent_results) > 0
        assert isinstance(consumer._recent_results[0], DetectionResult)


class TestGetStats:
    """Test statistics."""

    def test_initial_stats(self, consumer: DetectionConsumer) -> None:
        stats = consumer.get_stats()
        assert stats["events_consumed"] == 0
        assert stats["anomalies_detected"] == 0
        assert stats["scores_produced"] == 0

    def test_stats_after_processing(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        consumer._buffers["conn"] = [MagicMock()]

        with patch("src.detection_consumer.detection_context"):
            consumer._process_batch()

        stats = consumer.get_stats()
        assert stats["scores_produced"] > 0
        assert stats["anomalies_detected"] > 0


class TestGetRecentResults:
    """Test recent results retrieval."""

    def test_get_recent_results_empty(self, consumer: DetectionConsumer) -> None:
        results = consumer.get_recent_results()
        assert results == []

    def test_get_recent_results_with_limit(
        self, consumer: DetectionConsumer, mock_orchestrator: MagicMock
    ) -> None:
        consumer._buffers["conn"] = [MagicMock()]

        with patch("src.detection_consumer.detection_context"):
            consumer._process_batch()

        results = consumer.get_recent_results(limit=10)
        assert len(results) <= 10


class TestStartStop:
    """Test start/stop."""

    def test_start_creates_thread(self, consumer: DetectionConsumer) -> None:
        with patch.object(consumer, "_run"):
            consumer.start()
            assert consumer._thread is not None
            consumer.stop()

    def test_stop_joins_thread(self, consumer: DetectionConsumer) -> None:
        with patch.object(consumer, "_run"):
            consumer.start()
            consumer.stop()
            assert consumer._thread is None

    def test_start_when_already_running(self, consumer: DetectionConsumer) -> None:
        consumer._running = True
        consumer.start()  # should not create a new thread
        assert consumer._thread is None
        consumer._running = False
