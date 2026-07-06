"""Tests for TuningConsumer — uses mock consumer and label sources."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.models import TuningLabel
from src.tuning_consumer import TuningConsumer


@pytest.fixture
def config() -> PipelineConfig:
    return PipelineConfig()


@pytest.fixture
def consumer(config: PipelineConfig) -> TuningConsumer:
    return TuningConsumer(config)


def _make_suricata_payload() -> dict:
    """Create a realistic Suricata alert payload."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "abc123hash",
        "dst_ip": "def456hash",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "tcp",
        "alert_signature": "ET SCAN Nmap TCP SYN scan",
        "alert_category": "Network Scan",
        "alert_severity": 2,
        "rule_id": "2000001",
        "mitre_attack_id": "T1046",
        "flow_id": "flow-123",
    }


def _make_wazuh_payload() -> dict:
    """Create a realistic Wazuh event payload."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "001",
        "agent_name": "agent-1",
        "src_ip": "abc123hash",
        "dst_ip": "def456hash",
        "rule_id": "5710",
        "rule_level": 10,
        "rule_description": "Multiple authentication failures",
        "rule_groups": ["authentication", "attacks"],
        "event_type": "auth",
        "full_log": "Test log entry",
    }


def _make_ml_score_payload() -> dict:
    """Create a realistic ml-scores payload."""
    return {
        "event_id": "test-event-1",
        "model_scores": {"isolation_forest": 0.8, "autoencoder": 0.6},
        "fused_score": 0.7,
        "is_anomaly": True,
        "threshold": 0.5,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "abc123hash",
        "dst_ip": "def456hash",
    }


class TestTuningConsumerInit:
    """Test initialization."""

    def test_init(self, config: PipelineConfig) -> None:
        tc = TuningConsumer(config)
        assert tc.config is config
        assert tc._labelers is None
        assert tc._supervisor is None
        assert tc._events_consumed == 0

    def test_ensure_components_lazy(self, consumer: TuningConsumer) -> None:
        with (
            patch("src.tuning_consumer.create_tuning_labelers") as mock_labelers,
            patch("src.tuning_consumer.create_weak_supervisor") as mock_supervisor,
            patch("src.tuning_consumer.create_active_learning_selector") as mock_al,
        ):
            mock_labelers.return_value = {
                "suricata": MagicMock(),
                "wazuh": MagicMock(),
            }
            mock_supervisor.return_value = MagicMock()
            mock_al.return_value = MagicMock()

            consumer._ensure_components()

            assert consumer._labelers is not None
            assert consumer._supervisor is not None
            assert consumer._active_learner is not None


class TestProcessSuricata:
    """Test Suricata alert processing."""

    def test_process_suricata_creates_label(self, consumer: TuningConsumer) -> None:
        msg = MagicMock()
        msg.topic = "suricata-alerts"
        msg.value = _make_suricata_payload()

        # Mock the labeler and supervisor
        mock_labeler = MagicMock()
        mock_weak_label = MagicMock()
        mock_weak_label.source = "suricata"
        mock_labeler.generate_labels.return_value = [mock_weak_label]

        consumer._labelers = {"suricata": mock_labeler}
        consumer._supervisor = MagicMock()

        # Mock _parse_suricata_alert to return a mock alert
        mock_alert = MagicMock()
        with patch.object(consumer, "_parse_suricata_alert", return_value=mock_alert):
            consumer._process_suricata(msg)

        assert len(consumer._pending_labels) == 1
        assert consumer._labels_by_source["suricata"] == 1

    def test_process_suricata_invalid_payload(self, consumer: TuningConsumer) -> None:
        msg = MagicMock()
        msg.topic = "suricata-alerts"
        msg.value = "not a dict"

        consumer._process_suricata(msg)
        assert len(consumer._pending_labels) == 0

    def test_process_suricata_parse_failure(self, consumer: TuningConsumer) -> None:
        msg = MagicMock()
        msg.topic = "suricata-alerts"
        msg.value = {"bad": "data"}

        consumer._labelers = {"suricata": MagicMock()}
        consumer._supervisor = MagicMock()

        with patch.object(consumer, "_parse_suricata_alert", return_value=None):
            consumer._process_suricata(msg)

        assert len(consumer._pending_labels) == 0


class TestProcessWazuh:
    """Test Wazuh event processing."""

    def test_process_wazuh_creates_label(self, consumer: TuningConsumer) -> None:
        msg = MagicMock()
        msg.topic = "wazuh-events"
        msg.value = _make_wazuh_payload()

        mock_labeler = MagicMock()
        mock_weak_label = MagicMock()
        mock_weak_label.source = "wazuh"
        mock_labeler.generate_labels.return_value = [mock_weak_label]

        consumer._labelers = {"wazuh": mock_labeler}
        consumer._supervisor = MagicMock()

        mock_alert = MagicMock()
        with patch.object(consumer, "_parse_wazuh_alert", return_value=mock_alert):
            consumer._process_wazuh(msg)

        assert len(consumer._pending_labels) == 1
        assert consumer._labels_by_source["wazuh"] == 1


class TestProcessMlScores:
    """Test ml-scores processing."""

    def test_process_ml_scores_stores_in_buffer(self, consumer: TuningConsumer) -> None:
        msg = MagicMock()
        msg.topic = "ml-scores"
        msg.value = _make_ml_score_payload()

        consumer._process_ml_scores(msg)

        assert "test-event-1" in consumer._score_buffer
        assert consumer._score_buffer["test-event-1"]["fused_score"] == 0.7

    def test_process_ml_scores_trims_buffer(self, consumer: TuningConsumer) -> None:
        consumer._max_buffer_size = 5

        for i in range(10):
            msg = MagicMock()
            msg.topic = "ml-scores"
            msg.value = {
                "event_id": f"event-{i}",
                "model_scores": {},
                "fused_score": 0.5,
            }
            consumer._process_ml_scores(msg)

        assert len(consumer._score_buffer) <= 10


class TestCombineAndProduce:
    """Test label combination and incident production."""

    def test_combine_and_produce_empty(self, consumer: TuningConsumer) -> None:
        consumer._supervisor = MagicMock()
        consumer._combine_and_produce()
        consumer._supervisor.combine_labels.assert_not_called()

    def test_combine_and_produce_with_labels(self, consumer: TuningConsumer) -> None:
        mock_label = MagicMock()
        consumer._pending_labels = [mock_label, mock_label]

        mock_consensus = MagicMock()
        mock_consensus.label = True
        mock_consensus.confidence = 0.8
        mock_consensus.event_id = "test-1"
        mock_consensus.src_ip = "hash1"
        mock_consensus.dst_ip = "hash2"
        mock_consensus.timestamp = datetime.now(timezone.utc)
        mock_consensus.contributing_sources = ["suricata"]
        mock_consensus.vote_breakdown = {}
        mock_consensus.votes_positive = 1
        mock_consensus.votes_negative = 0
        mock_consensus.mitre_attack_id = "T1046"
        mock_consensus.event_type = "scan"

        consumer._supervisor = MagicMock()
        consumer._supervisor.combine_labels.return_value = [mock_consensus]

        with (
            patch("src.tuning_consumer.tuning_context"),
            patch.object(consumer, "_produce_incident") as mock_produce,
        ):
            consumer._combine_and_produce()

            mock_produce.assert_called_once_with(mock_consensus)
            assert len(consumer._pending_labels) == 0


class TestSubmitAnalystFeedback:
    """Test analyst feedback submission."""

    def test_submit_analyst_feedback(self, consumer: TuningConsumer) -> None:
        consumer._score_buffer["test-event-1"] = {
            "src_ip": "hash1",
            "dst_ip": "hash2",
        }

        mock_labeler = MagicMock()
        mock_weak_label = MagicMock()
        mock_labeler.generate_labels.return_value = [mock_weak_label]

        consumer._labelers = {
            "suricata": MagicMock(),
            "wazuh": MagicMock(),
            "misp": MagicMock(),
            "analyst": mock_labeler,
        }
        consumer._supervisor = MagicMock()
        consumer._supervisor.combine_labels.return_value = []

        mock_feedback = MagicMock()
        with (
            patch.object(
                consumer, "_create_analyst_feedback", return_value=mock_feedback
            ),
            patch("src.tuning_consumer.tuning_context"),
        ):
            result = consumer.submit_analyst_feedback(
                event_id="test-event-1",
                label=True,
                comment="Confirmed anomaly",
            )

        assert isinstance(result, TuningLabel)
        assert result.source == "analyst"
        assert result.label is True
        assert result.confidence == 1.0
        assert consumer._labels_by_source["analyst"] == 1


class TestGetStats:
    """Test statistics."""

    def test_initial_stats(self, consumer: TuningConsumer) -> None:
        stats = consumer.get_stats()
        assert stats["labels_by_source"] == {}
        assert stats["active_learning_queries"] == 0
        assert stats["incidents_produced"] == 0
        assert stats["events_consumed"] == 0
        assert stats["score_buffer_size"] == 0

    def test_stats_after_processing(self, consumer: TuningConsumer) -> None:
        msg = MagicMock()
        msg.topic = "ml-scores"
        msg.value = _make_ml_score_payload()
        consumer._process_ml_scores(msg)

        stats = consumer.get_stats()
        assert stats["score_buffer_size"] == 1


class TestStartStop:
    """Test start/stop."""

    def test_start_creates_thread(self, consumer: TuningConsumer) -> None:
        with patch.object(consumer, "_run"):
            consumer.start()
            assert consumer._thread is not None
            consumer.stop()

    def test_stop_joins_thread(self, consumer: TuningConsumer) -> None:
        with patch.object(consumer, "_run"):
            consumer.start()
            consumer.stop()
            assert consumer._thread is None

    def test_start_when_already_running(self, consumer: TuningConsumer) -> None:
        consumer._running = True
        consumer.start()
        assert consumer._thread is None
        consumer._running = False
