"""Tests for SensorSimulator — uses mock KafkaProducer, no real broker."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.models import SensorEvent
from src.sensor_simulator import SensorSimulator


@pytest.fixture
def config() -> PipelineConfig:
    return PipelineConfig(sensor_rate=100, anomaly_ratio=0.5)


@pytest.fixture
def mock_producer() -> MagicMock:
    producer = MagicMock()
    producer.send.return_value = MagicMock()
    return producer


@pytest.fixture
def simulator(config: PipelineConfig, mock_producer: MagicMock) -> SensorSimulator:
    return SensorSimulator(config, producer=mock_producer)


def _make_mock_zeek_event() -> MagicMock:
    """Create a mock Zeek event with a real datetime timestamp."""
    mock_event = MagicMock()
    mock_event.model_dump.return_value = {
        "timestamp": "2026-07-01T00:00:00+00:00",
        "uid": "abc123",
        "src_ip": "hash1",
        "dst_ip": "hash2",
    }
    mock_event.timestamp = datetime(2026, 7, 1, tzinfo=timezone.utc)
    mock_event.src_ip = "hash1"
    return mock_event


class TestSensorSimulatorInit:
    """Test initialization."""

    def test_init_with_producer(
        self, config: PipelineConfig, mock_producer: MagicMock
    ) -> None:
        sim = SensorSimulator(config, producer=mock_producer)
        assert sim.config is config
        assert sim._producer is mock_producer

    def test_init_without_producer(self, config: PipelineConfig) -> None:
        sim = SensorSimulator(config)
        assert sim._producer is None


class TestProduceZeekConn:
    """Test Zeek conn event production."""

    def test_produce_zeek_conn_sends_to_kafka(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            result = simulator.produce_zeek_conn()

            assert isinstance(result, SensorEvent)
            assert result.event_type == "zeek_conn"
            assert result.source == "zeek"
            mock_producer.send.assert_called_once()
            call_args = mock_producer.send.call_args
            assert call_args[0][0] == "zeek-conn"

    def test_produce_zeek_conn_stats_updated(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            simulator.produce_zeek_conn()

            stats = simulator.get_stats()
            assert stats["events_by_type"]["zeek_conn"] == 1
            assert stats["total_produced"] == 1


class TestProduceZeekDns:
    """Test Zeek DNS event production."""

    def test_produce_zeek_dns_sends_to_kafka(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            result = simulator.produce_zeek_dns()

            assert result.event_type == "zeek_dns"
            mock_producer.send.assert_called_once()
            assert mock_producer.send.call_args[0][0] == "zeek-dns"


class TestProduceZeekHttp:
    """Test Zeek HTTP event production."""

    def test_produce_zeek_http_sends_to_kafka(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            result = simulator.produce_zeek_http()

            assert result.event_type == "zeek_http"
            mock_producer.send.assert_called_once()
            assert mock_producer.send.call_args[0][0] == "zeek-http"


class TestProduceZeekSsl:
    """Test Zeek SSL event production."""

    def test_produce_zeek_ssl_sends_to_kafka(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            result = simulator.produce_zeek_ssl()

            assert result.event_type == "zeek_ssl"
            mock_producer.send.assert_called_once()
            assert mock_producer.send.call_args[0][0] == "zeek-ssl"


class TestProduceSuricataAlert:
    """Test Suricata alert production."""

    def test_produce_suricata_alert_sends_to_kafka(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        result = simulator.produce_suricata_alert()

        assert result.event_type == "suricata_alert"
        assert result.source == "suricata"
        assert result.is_anomaly is True
        mock_producer.send.assert_called_once()
        assert mock_producer.send.call_args[0][0] == "suricata-alerts"

    def test_produce_suricata_alert_has_required_fields(
        self, simulator: SensorSimulator
    ) -> None:
        result = simulator.produce_suricata_alert()

        assert "timestamp" in result.data
        assert "src_ip" in result.data
        assert "dst_ip" in result.data
        assert "alert_signature" in result.data
        assert "alert_category" in result.data
        assert "alert_severity" in result.data

    def test_produce_suricata_alert_stats(self, simulator: SensorSimulator) -> None:
        simulator.produce_suricata_alert()
        stats = simulator.get_stats()
        assert stats["events_by_type"]["suricata_alert"] == 1
        assert stats["anomaly_count"] == 1


class TestProduceWazuhEvent:
    """Test Wazuh event production."""

    def test_produce_wazuh_event_sends_to_kafka(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        result = simulator.produce_wazuh_event()

        assert result.event_type == "wazuh_event"
        assert result.source == "wazuh"
        assert result.is_anomaly is True
        mock_producer.send.assert_called_once()
        assert mock_producer.send.call_args[0][0] == "wazuh-events"

    def test_produce_wazuh_event_has_required_fields(
        self, simulator: SensorSimulator
    ) -> None:
        result = simulator.produce_wazuh_event()

        assert "timestamp" in result.data
        assert "agent_id" in result.data
        assert "rule_id" in result.data
        assert "rule_level" in result.data
        assert "rule_description" in result.data


class TestProduceBatch:
    """Test batch production."""

    def test_produce_batch_generates_n_events(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            results = simulator.produce_batch(20)

            assert len(results) == 20
            assert mock_producer.send.call_count == 20

    def test_produce_batch_stats(
        self, simulator: SensorSimulator, mock_producer: MagicMock
    ) -> None:
        with patch("src.sensor_simulator.generate_synthetic_zeek_logs") as mock_gen:
            mock_gen.return_value = [_make_mock_zeek_event()]

            simulator.produce_batch(10)

            stats = simulator.get_stats()
            assert stats["total_produced"] == 10


class TestGetStats:
    """Test statistics."""

    def test_initial_stats(self, simulator: SensorSimulator) -> None:
        stats = simulator.get_stats()
        assert stats["total_produced"] == 0
        assert stats["anomaly_count"] == 0
        assert stats["anomaly_ratio"] == 0.0

    def test_anomaly_ratio_calculation(self, simulator: SensorSimulator) -> None:
        # Produce some suricata alerts (always anomalies)
        for _ in range(5):
            simulator.produce_suricata_alert()

        stats = simulator.get_stats()
        assert stats["anomaly_count"] == 5
        assert stats["total_produced"] == 5
        assert stats["anomaly_ratio"] == 1.0


class TestStartStop:
    """Test start/stop functionality."""

    def test_stop_sets_running_false(self, simulator: SensorSimulator) -> None:
        simulator._running = True
        simulator.stop()
        assert simulator._running is False
