"""Tests for baseline calculator."""

from __future__ import annotations

import json

import pytest

from src.baseline import BaselineCalculator, BASELINE_METRICS
from src.models import BaselineStats, ZeekConn
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs


@pytest.fixture
def trained_baseline(sample_conn_events, sample_dns_events):
    """A baseline calculator with computed stats."""
    calc = BaselineCalculator(window_hours=24)
    calc.calculate_baseline(sample_conn_events, sample_dns_events)
    return calc


class TestBaselineCalculation:
    """Tests for baseline calculation."""

    def test_calculate_basic(self, sample_conn_events, sample_dns_events):
        """calculate_baseline produces BaselineStats list."""
        calc = BaselineCalculator(window_hours=24)
        stats = calc.calculate_baseline(sample_conn_events, sample_dns_events)
        assert len(stats) > 0
        assert all(isinstance(s, BaselineStats) for s in stats)

    def test_calculate_metrics(self, trained_baseline):
        """All expected metrics are computed."""
        metrics = {s.metric for s in trained_baseline.stats}
        for expected in BASELINE_METRICS:
            assert expected in metrics

    def test_calculate_percentiles(self, trained_baseline):
        """Percentiles are correctly ordered."""
        for stat in trained_baseline.stats:
            assert stat.min_val <= stat.p50
            assert stat.p50 <= stat.p95
            assert stat.p95 <= stat.p99
            assert stat.p99 <= stat.max_val

    def test_calculate_mean_std(self, trained_baseline):
        """Mean and std are non-negative."""
        for stat in trained_baseline.stats:
            assert stat.mean >= 0
            assert stat.std >= 0

    def test_calculate_sample_count(self, trained_baseline):
        """Sample count is positive."""
        for stat in trained_baseline.stats:
            assert stat.sample_count > 0

    def test_calculate_window_hours(self, trained_baseline):
        """Window hours is stored correctly."""
        for stat in trained_baseline.stats:
            assert stat.window_hours == 24

    def test_calculate_empty_events(self):
        """Calculating with empty events returns empty list."""
        calc = BaselineCalculator()
        stats = calc.calculate_baseline([], [])
        assert stats == []

    def test_calculate_no_dns(self, sample_conn_events):
        """Calculating without DNS events still works."""
        calc = BaselineCalculator()
        stats = calc.calculate_baseline(sample_conn_events, None)
        assert len(stats) > 0

    def test_calculate_with_synthetic_data(self):
        """Calculate baseline from synthetic data."""
        conn = generate_zeek_conn_logs(n_events=500, seed=42)
        dns = generate_zeek_dns_logs(n_events=100, seed=42)
        calc = BaselineCalculator(window_hours=48)
        stats = calc.calculate_baseline(conn, dns)
        assert len(stats) > 0
        # Should have stats for multiple hosts
        hosts = {s.src_ip for s in stats}
        assert len(hosts) > 1

    def test_calculate_groups_by_host_service(self, trained_baseline):
        """Stats are grouped by (src_ip, service)."""
        groups = {(s.src_ip, s.service) for s in trained_baseline.stats}
        assert len(groups) > 0


class TestGetBaselineForHost:
    """Tests for get_baseline_for_host."""

    def test_get_baseline_for_host_basic(self, trained_baseline, src_ip_a):
        """Get baseline for a specific host."""
        stats = trained_baseline.get_baseline_for_host(src_ip_a)
        assert len(stats) > 0
        for s in stats:
            assert s.src_ip == src_ip_a

    def test_get_baseline_for_host_with_service(self, trained_baseline, src_ip_a):
        """Get baseline for a specific host and service."""
        stats = trained_baseline.get_baseline_for_host(src_ip_a, "ssl")
        assert len(stats) > 0
        for s in stats:
            assert s.src_ip == src_ip_a
            assert s.service == "ssl"

    def test_get_baseline_nonexistent_host(self, trained_baseline):
        """Get baseline for a nonexistent host returns empty list."""
        stats = trained_baseline.get_baseline_for_host("nonexistent_hash")
        assert stats == []


class TestCompareToBaseline:
    """Tests for compare_to_baseline."""

    def test_compare_basic(self, trained_baseline, sample_conn):
        """Compare an event to baseline."""
        result = trained_baseline.compare_to_baseline(sample_conn)
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_compare_metrics(self, trained_baseline, sample_conn):
        """Comparison includes expected metrics."""
        result = trained_baseline.compare_to_baseline(sample_conn)
        assert "bytes_out" in result
        assert "bytes_in" in result
        assert "duration" in result
        assert "pkts_total" in result

    def test_compare_z_scores(self, trained_baseline, sample_conn):
        """Z-scores are computed."""
        result = trained_baseline.compare_to_baseline(sample_conn)
        for metric, data in result.items():
            assert "z_score" in data
            assert isinstance(data["z_score"], float)

    def test_compare_ratio_vs_p99(self, trained_baseline, sample_conn):
        """Ratio vs p99 is computed."""
        result = trained_baseline.compare_to_baseline(sample_conn)
        for metric, data in result.items():
            assert "ratio_vs_p99" in data
            assert isinstance(data["ratio_vs_p99"], float)

    def test_compare_is_anomaly_flag(self, trained_baseline, sample_conn):
        """is_anomaly flag is present."""
        result = trained_baseline.compare_to_baseline(sample_conn)
        for metric, data in result.items():
            assert "is_anomaly" in data
            assert isinstance(data["is_anomaly"], bool)

    def test_compare_anomalous_event(self, trained_baseline):
        """An anomalous event (high bytes) is flagged."""
        # Find the baseline for bytes_out
        anomalous_conn = ZeekConn(
            timestamp=sample_conn_events_ts(),
            uid="test-anom",
            src_ip=trained_baseline.stats[0].src_ip,
            dst_ip="dst_hash",
            src_port=50000,
            dst_port=443,
            protocol="tcp",
            duration=1.0,
            orig_bytes=100_000_000,  # Very high
            resp_bytes=100,
            orig_pkts=1000,
            resp_pkts=10,
            service="ssl",
            conn_state="SF",
        )
        result = trained_baseline.compare_to_baseline(anomalous_conn)
        assert result["bytes_out"]["is_anomaly"]


def sample_conn_events_ts():
    """Helper for timestamp."""
    from datetime import datetime, timezone

    return datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)


class TestBaselineSerialization:
    """Tests for serialization."""

    def test_to_dict_basic(self, trained_baseline):
        """to_dict produces a serializable dict."""
        d = trained_baseline.to_dict()
        assert "window_hours" in d
        assert "stats" in d
        assert isinstance(d["stats"], list)

    def test_to_dict_json_serializable(self, trained_baseline):
        """to_dict output is JSON serializable."""
        d = trained_baseline.to_dict()
        json_str = json.dumps(d, default=str)
        assert len(json_str) > 0

    def test_from_dict_roundtrip(self, trained_baseline):
        """from_dict restores the baseline correctly."""
        d = trained_baseline.to_dict()
        restored = BaselineCalculator.from_dict(d)
        assert restored.window_hours == trained_baseline.window_hours
        assert len(restored.stats) == len(trained_baseline.stats)

    def test_from_dict_empty(self):
        """from_dict with empty data creates empty baseline."""
        calc = BaselineCalculator.from_dict({})
        assert calc.window_hours == 24
        assert len(calc.stats) == 0

    def test_from_dict_preserves_stats(self, trained_baseline):
        """from_dict preserves stat values."""
        d = trained_baseline.to_dict()
        restored = BaselineCalculator.from_dict(d)
        for orig, rest in zip(trained_baseline.stats, restored.stats):
            assert orig.src_ip == rest.src_ip
            assert orig.metric == rest.metric
            assert orig.mean == rest.mean
            assert orig.p99 == rest.p99
