"""Tests for Pydantic v2 models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.models import (
    BaselineStats,
    FeatureVector,
    ModelResult,
    StateMapping,
    WindowFeatures,
    ZeekConn,
    ZeekDNS,
    ZeekHTTP,
    ZeekSSL,
    _parse_timestamp,
)


class TestParseTimestamp:
    """Tests for the _parse_timestamp helper."""

    def test_datetime_input(self, now_utc):
        """Datetime is returned with timezone."""
        result = _parse_timestamp(now_utc)
        assert result == now_utc
        assert result.tzinfo is not None

    def test_naive_datetime_gets_utc(self):
        """Naive datetime gets UTC timezone."""
        naive = datetime(2026, 7, 1, 12, 0, 0)
        result = _parse_timestamp(naive)
        assert result.tzinfo == timezone.utc

    def test_iso_string_with_z(self):
        """ISO-8601 string with 'Z' suffix."""
        result = _parse_timestamp("2026-07-01T12:00:00Z")
        assert result.year == 2026
        assert result.hour == 12

    def test_iso_string_without_z(self):
        """ISO-8601 string without 'Z' suffix."""
        result = _parse_timestamp("2026-07-01T12:00:00+00:00")
        assert result.year == 2026

    def test_epoch_float(self):
        """Epoch float is converted to datetime."""
        result = _parse_timestamp(1700000000.0)
        assert result.year == 2023

    def test_epoch_int(self):
        """Epoch int is converted to datetime."""
        result = _parse_timestamp(1700000000)
        assert result.tzinfo is not None

    def test_invalid_input(self):
        """Invalid input raises ValueError."""
        with pytest.raises(ValueError):
            _parse_timestamp("not-a-timestamp")


class TestZeekConn:
    """Tests for ZeekConn model."""

    def test_basic_creation(self, sample_conn):
        """ZeekConn can be created with valid data."""
        assert sample_conn.uid == "abc123def456"
        assert sample_conn.src_port == 54321
        assert sample_conn.protocol == "tcp"

    def test_timestamp_validator(self):
        """Timestamp validator accepts ISO string."""
        conn = ZeekConn(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=80,
            dst_port=443,
            protocol="tcp",
            duration=1.0,
            orig_bytes=100,
            resp_bytes=200,
            orig_pkts=5,
            resp_pkts=10,
        )
        assert conn.timestamp.tzinfo is not None

    def test_extra_ignore(self):
        """Extra fields are ignored."""
        conn = ZeekConn(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=80,
            dst_port=443,
            protocol="tcp",
            duration=1.0,
            orig_bytes=100,
            resp_bytes=200,
            orig_pkts=5,
            resp_pkts=10,
            extra_field="should_be_ignored",
        )
        assert not hasattr(conn, "extra_field")

    def test_bytes_total_property(self, sample_conn):
        """bytes_total property returns orig + resp."""
        assert (
            sample_conn.bytes_total == sample_conn.orig_bytes + sample_conn.resp_bytes
        )

    def test_pkts_total_property(self, sample_conn):
        """pkts_total property returns orig + resp."""
        assert sample_conn.pkts_total == sample_conn.orig_pkts + sample_conn.resp_pkts

    def test_ts_epoch_property(self, sample_conn):
        """ts_epoch property returns epoch seconds."""
        assert sample_conn.ts_epoch > 0

    def test_optional_fields(self):
        """Optional fields default to None."""
        conn = ZeekConn(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=80,
            dst_port=443,
            protocol="tcp",
            duration=1.0,
            orig_bytes=100,
            resp_bytes=200,
            orig_pkts=5,
            resp_pkts=10,
        )
        assert conn.service is None
        assert conn.conn_state is None


class TestZeekDNS:
    """Tests for ZeekDNS model."""

    def test_basic_creation(self, sample_dns):
        """ZeekDNS can be created with valid data."""
        assert sample_dns.query == "example.com"
        assert sample_dns.dst_port == 53

    def test_is_nxdomain_property(self, sample_dns):
        """is_nxdomain property returns False for NOERROR."""
        assert sample_dns.is_nxdomain is False

    def test_is_nxdomain_true(self):
        """is_nxdomain returns True for NXDOMAIN."""
        dns = ZeekDNS(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=50000,
            dst_port=53,
            protocol="udp",
            query="nonexistent.com",
            rcode="NXDOMAIN",
        )
        assert dns.is_nxdomain is True

    def test_default_values(self):
        """Default values are set correctly."""
        dns = ZeekDNS(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=50000,
            dst_port=53,
            protocol="udp",
            query="example.com",
        )
        assert dns.qclass == 0
        assert dns.qtype == "A"
        assert dns.rcode == "NOERROR"
        assert dns.answers == []
        assert dns.ttl == []


class TestZeekHTTP:
    """Tests for ZeekHTTP model."""

    def test_basic_creation(self, sample_http):
        """ZeekHTTP can be created with valid data."""
        assert sample_http.method == "GET"
        assert sample_http.host == "example.com"

    def test_default_values(self):
        """Default values are set correctly."""
        http = ZeekHTTP(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=50000,
            dst_port=80,
            method="GET",
            host="example.com",
            uri="/",
        )
        assert http.user_agent is None
        assert http.status_code is None
        assert http.request_body_len == 0
        assert http.response_body_len == 0


class TestZeekSSL:
    """Tests for ZeekSSL model."""

    def test_basic_creation(self, sample_ssl):
        """ZeekSSL can be created with valid data."""
        assert sample_ssl.version == "TLSv1.2"
        assert sample_ssl.server_name == "example.com"

    def test_default_values(self):
        """Default values are set correctly."""
        ssl = ZeekSSL(
            timestamp="2026-07-01T12:00:00Z",
            uid="test",
            src_ip="hash1",
            dst_ip="hash2",
            src_port=50000,
            dst_port=443,
        )
        assert ssl.version is None
        assert ssl.cipher is None
        assert ssl.server_name is None
        assert ssl.resumed is False


class TestFeatureVector:
    """Tests for FeatureVector model."""

    def test_basic_creation(self, sample_feature_vector):
        """FeatureVector can be created with valid data."""
        assert sample_feature_vector.duration == 1.5
        assert sample_feature_vector.bytes_total == 55000

    def test_normalized_default_empty(self, sample_feature_vector):
        """normalized field defaults to empty list."""
        assert sample_feature_vector.normalized == []

    def test_aggregated_defaults(self):
        """Aggregated features default to 0."""
        fv = FeatureVector(
            timestamp="2026-07-01T12:00:00Z",
            src_ip="hash1",
            dst_ip="hash2",
            duration=1.0,
            orig_bytes=100,
            resp_bytes=200,
            orig_pkts=5,
            resp_pkts=10,
            bytes_total=300,
            bytes_ratio=0.33,
            dst_port=443,
            is_common_port=True,
            hour_of_day=12.0,
            day_of_week=2.0,
            is_weekend=False,
        )
        assert fv.unique_destinations == 0
        assert fv.unique_ports == 0
        assert fv.dns_queries_count == 0
        assert fv.nxdomain_ratio == 0.0
        assert fv.avg_dns_query_length == 0.0


class TestWindowFeatures:
    """Tests for WindowFeatures model."""

    def test_basic_creation(self, sample_window_features):
        """WindowFeatures can be created with valid data."""
        assert len(sample_window_features) > 0
        w = sample_window_features[0]
        assert w.bytes_out >= 0
        assert w.connection_count > 0

    def test_timestamp_validators(self):
        """All timestamp fields accept ISO strings."""
        w = WindowFeatures(
            timestamp="2026-07-01T12:00:00Z",
            src_ip="hash1",
            window_start="2026-07-01T12:00:00Z",
            window_end="2026-07-01T12:05:00Z",
            bytes_out=1000,
            bytes_in=5000,
            pkts_total=100,
            unique_destinations=5,
            unique_ports=3,
            dns_queries=10,
            nxdomain_ratio=0.1,
            avg_duration=1.5,
            connection_count=20,
        )
        assert w.timestamp.tzinfo is not None
        assert w.window_start.tzinfo is not None
        assert w.window_end.tzinfo is not None


class TestModelResult:
    """Tests for ModelResult model."""

    def test_basic_creation(self, sample_model_result):
        """ModelResult can be created with valid data."""
        assert sample_model_result.model_name == "isolation_forest"
        assert sample_model_result.score == 0.85

    def test_score_clamping(self):
        """Score is clamped to 0-1 range."""
        result = ModelResult(
            model_name="test",
            timestamp="2026-07-01T12:00:00Z",
            src_ip="hash1",
            score=1.5,
        )
        assert result.score == 1.0

        result2 = ModelResult(
            model_name="test",
            timestamp="2026-07-01T12:00:00Z",
            src_ip="hash1",
            score=-0.5,
        )
        assert result2.score == 0.0

    def test_default_event_id(self):
        """event_id is auto-generated."""
        result = ModelResult(
            model_name="test",
            timestamp="2026-07-01T12:00:00Z",
            src_ip="hash1",
            score=0.5,
        )
        assert result.event_id is not None
        assert len(result.event_id) > 0

    def test_details_default_empty(self):
        """details defaults to empty dict."""
        result = ModelResult(
            model_name="test",
            timestamp="2026-07-01T12:00:00Z",
            src_ip="hash1",
            score=0.5,
        )
        assert result.details == {}


class TestBaselineStats:
    """Tests for BaselineStats model."""

    def test_basic_creation(self, sample_baseline_stats):
        """BaselineStats can be created with valid data."""
        assert sample_baseline_stats.metric == "bytes_out"
        assert sample_baseline_stats.mean == 5000.0

    def test_window_hours_default(self):
        """window_hours defaults to 24."""
        stat = BaselineStats(
            src_ip="hash1",
            metric="bytes_out",
            mean=100.0,
            std=50.0,
            min_val=10.0,
            max_val=500.0,
            p50=90.0,
            p95=400.0,
            p99=490.0,
            sample_count=100,
        )
        assert stat.window_hours == 24


class TestStateMapping:
    """Tests for StateMapping model."""

    def test_basic_creation(self):
        """StateMapping can be created with valid data."""
        mapping = StateMapping(
            state_id=0,
            label="normal",
            confidence=0.9,
            mean_features={"bytes_out": 1000.0},
        )
        assert mapping.state_id == 0
        assert mapping.label == "normal"

    def test_confidence_range(self):
        """Confidence outside 0-1 raises validation error."""
        with pytest.raises(Exception):
            StateMapping(
                state_id=0,
                label="normal",
                confidence=1.5,
            )

    def test_mean_features_default(self):
        """mean_features defaults to empty dict."""
        mapping = StateMapping(
            state_id=0,
            label="normal",
            confidence=0.5,
        )
        assert mapping.mean_features == {}
