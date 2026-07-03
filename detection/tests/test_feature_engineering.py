"""Tests for feature engineering module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from src.feature_engineering import (
    ALL_FEATURE_COLUMNS,
    DEFAULT_COMMON_PORTS,
    extract_event_features,
    extract_window_features,
    get_feature_matrix,
    normalize_features,
)
from src.models import FeatureVector, WindowFeatures
from src.synthetic_data import generate_zeek_conn_logs, generate_zeek_dns_logs


# ---------------------------------------------------------------------------
# Event feature extraction
# ---------------------------------------------------------------------------


class TestExtractEventFeatures:
    """Tests for extract_event_features."""

    def test_extract_basic(self, sample_conn_events, sample_dns_events):
        """Basic extraction produces FeatureVector list."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        assert len(vectors) == len(sample_conn_events)
        assert all(isinstance(v, FeatureVector) for v in vectors)

    def test_extract_connection_features(self, sample_conn_events, sample_dns_events):
        """Verify connection-level features are correct."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        for i, vector in enumerate(vectors):
            conn = sample_conn_events[i]
            assert vector.duration == conn.duration
            assert vector.orig_bytes == conn.orig_bytes
            assert vector.resp_bytes == conn.resp_bytes
            assert vector.orig_pkts == conn.orig_pkts
            assert vector.resp_pkts == conn.resp_pkts
            assert vector.bytes_total == conn.orig_bytes + conn.resp_bytes

    def test_extract_bytes_ratio(self, sample_conn_events, sample_dns_events):
        """Verify bytes_ratio is orig/total."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        for i, vector in enumerate(vectors):
            conn = sample_conn_events[i]
            total = conn.orig_bytes + conn.resp_bytes
            if total > 0:
                assert abs(vector.bytes_ratio - conn.orig_bytes / total) < 1e-6
            else:
                assert vector.bytes_ratio == 0.0

    def test_extract_dst_port_and_common(self, sample_conn_events, sample_dns_events):
        """Verify dst_port and is_common_port."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        for i, vector in enumerate(vectors):
            conn = sample_conn_events[i]
            assert vector.dst_port == conn.dst_port
            assert vector.is_common_port == (conn.dst_port in DEFAULT_COMMON_PORTS)

    def test_extract_temporal_features(self, sample_conn_events, sample_dns_events):
        """Verify temporal features (hour, day, weekend)."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        for i, vector in enumerate(vectors):
            ts = sample_conn_events[i].timestamp
            assert vector.hour_of_day == float(ts.hour)
            assert vector.day_of_week == float(ts.weekday())
            assert vector.is_weekend == (ts.weekday() >= 5)

    def test_extract_host_aggregates(self, sample_conn_events, sample_dns_events):
        """Verify host-aggregated features."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        # Each vector should have unique_destinations > 0
        for vector in vectors:
            assert vector.unique_destinations > 0
            assert vector.unique_ports > 0

    def test_extract_dns_features(self, sample_conn_events, sample_dns_events):
        """Verify DNS-related features."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        for vector in vectors:
            assert vector.dns_queries_count >= 0
            assert 0.0 <= vector.nxdomain_ratio <= 1.0
            assert vector.avg_dns_query_length >= 0.0

    def test_extract_empty_events(self):
        """Extracting from empty lists returns empty list."""
        vectors = extract_event_features([], [])
        assert vectors == []

    def test_extract_no_dns_events(self, sample_conn_events):
        """Extracting without DNS events still works."""
        vectors = extract_event_features(sample_conn_events, None)
        assert len(vectors) == len(sample_conn_events)
        for vector in vectors:
            assert vector.dns_queries_count == 0
            assert vector.nxdomain_ratio == 0.0

    def test_extract_with_synthetic_data(self):
        """Extract features from synthetic data."""
        conn = generate_zeek_conn_logs(n_events=100, seed=42)
        dns = generate_zeek_dns_logs(n_events=50, seed=42)
        vectors = extract_event_features(conn, dns)
        assert len(vectors) == 100
        assert all(v.bytes_total > 0 for v in vectors)

    def test_extract_normalized_field_empty(
        self, sample_conn_events, sample_dns_events
    ):
        """Normalized field should be empty before normalization."""
        vectors = extract_event_features(sample_conn_events, sample_dns_events)
        for vector in vectors:
            assert vector.normalized == []


# ---------------------------------------------------------------------------
# Window feature extraction
# ---------------------------------------------------------------------------


class TestExtractWindowFeatures:
    """Tests for extract_window_features."""

    def test_extract_window_basic(self, sample_conn_events):
        """Basic window extraction produces WindowFeatures list."""
        windows = extract_window_features(sample_conn_events, window_minutes=5)
        assert len(windows) > 0
        assert all(isinstance(w, WindowFeatures) for w in windows)

    def test_extract_window_fields(self, sample_conn_events):
        """Verify window feature fields."""
        windows = extract_window_features(sample_conn_events, window_minutes=5)
        for w in windows:
            assert w.bytes_out >= 0
            assert w.bytes_in >= 0
            assert w.pkts_total >= 0
            assert w.unique_destinations > 0
            assert w.unique_ports > 0
            assert w.dns_queries >= 0
            assert 0.0 <= w.nxdomain_ratio <= 1.0
            assert w.avg_duration >= 0.0
            assert w.connection_count > 0

    def test_extract_window_time_bounds(self, sample_conn_events):
        """Verify window_start and window_end."""
        windows = extract_window_features(sample_conn_events, window_minutes=5)
        for w in windows:
            assert w.window_end > w.window_start
            delta = w.window_end - w.window_start
            assert delta.total_seconds() == 300  # 5 minutes

    def test_extract_window_grouped_by_host(self, sample_conn_events):
        """Windows are grouped by src_ip."""
        windows = extract_window_features(sample_conn_events, window_minutes=5)
        src_ips = {w.src_ip for w in windows}
        assert len(src_ips) >= 1

    def test_extract_window_empty(self):
        """Extracting from empty events returns empty list."""
        windows = extract_window_features([], window_minutes=5)
        assert windows == []

    def test_extract_window_with_dns(self, sample_conn_events, sample_dns_events):
        """Window extraction with DNS events."""
        windows = extract_window_features(
            sample_conn_events, sample_dns_events, window_minutes=5
        )
        for w in windows:
            if w.dns_queries > 0:
                assert w.nxdomain_ratio >= 0.0

    def test_extract_window_sorted(self, sample_conn_events):
        """Windows are sorted by timestamp."""
        windows = extract_window_features(sample_conn_events, window_minutes=5)
        timestamps = [w.window_start for w in windows]
        assert timestamps == sorted(timestamps)

    def test_extract_window_different_sizes(self, sample_conn_events):
        """Different window sizes produce different numbers of windows."""
        w5 = extract_window_features(sample_conn_events, window_minutes=5)
        w10 = extract_window_features(sample_conn_events, window_minutes=10)
        # Larger windows → fewer or equal windows
        assert len(w10) <= len(w5) + len({w.src_ip for w in w5})


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


class TestNormalizeFeatures:
    """Tests for normalize_features."""

    def test_normalize_basic(self, sample_feature_vectors):
        """Basic normalization fills the normalized field."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        assert len(vectors) == len(sample_feature_vectors)
        for v in vectors:
            assert len(v.normalized) > 0

    def test_normalize_returns_scaler(self, sample_feature_vectors):
        """normalize_features returns a fitted scaler."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        assert scaler is not None
        assert hasattr(scaler, "mean_")
        assert hasattr(scaler, "scale_")

    def test_normalize_values_standardized(self, sample_feature_vectors):
        """Normalized values should have approximately zero mean."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        matrix = np.array([v.normalized for v in vectors])
        means = np.mean(matrix, axis=0)
        # Mean should be close to zero (within numerical precision)
        for m in means:
            assert abs(m) < 1e-6

    def test_normalize_with_existing_scaler(self, sample_feature_vectors):
        """Reusing a fitted scaler produces consistent results."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        first_normalized = [v.normalized[:] for v in vectors]

        # Re-normalize with the same scaler
        vectors2, scaler2 = normalize_features(sample_feature_vectors, scaler)
        for i, v in enumerate(vectors2):
            for j, val in enumerate(v.normalized):
                assert abs(val - first_normalized[i][j]) < 1e-6

    def test_normalize_empty(self):
        """Normalizing empty list returns empty list."""
        vectors, scaler = normalize_features([])
        assert vectors == []

    def test_normalize_feature_count(self, sample_feature_vectors):
        """Normalized vectors have the correct number of features."""
        vectors, scaler = normalize_features(sample_feature_vectors)
        expected = len(ALL_FEATURE_COLUMNS)
        for v in vectors:
            assert len(v.normalized) == expected


# ---------------------------------------------------------------------------
# Feature matrix
# ---------------------------------------------------------------------------


class TestGetFeatureMatrix:
    """Tests for get_feature_matrix."""

    def test_get_matrix_normalized(self, sample_feature_vectors):
        """Get matrix from normalized vectors."""
        vectors, _ = normalize_features(sample_feature_vectors)
        matrix = get_feature_matrix(vectors)
        assert matrix.shape == (len(vectors), len(ALL_FEATURE_COLUMNS))

    def test_get_matrix_raw(self, sample_feature_vectors):
        """Get matrix from unnormalized vectors (uses raw values)."""
        matrix = get_feature_matrix(sample_feature_vectors)
        assert matrix.shape == (len(sample_feature_vectors), len(ALL_FEATURE_COLUMNS))

    def test_get_matrix_empty(self):
        """Get matrix from empty list."""
        matrix = get_feature_matrix([])
        assert matrix.shape == (0, len(ALL_FEATURE_COLUMNS))
