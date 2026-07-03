"""Feature extraction and normalization for detection models.

Two outputs:
- ``extract_event_features``: per-event FeatureVector for Isolation Forest and Autoencoder
- ``extract_window_features``: aggregated WindowFeatures per 5-min window for HMM

Normalization uses StandardScaler from scikit-learn.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import structlog
from sklearn.preprocessing import StandardScaler

from src.models import (
    FeatureVector,
    WindowFeatures,
    ZeekConn,
    ZeekDNS,
    ZeekHTTP,
    ZeekSSL,
)

log = structlog.get_logger()

# Common ports for is_common_port feature
DEFAULT_COMMON_PORTS = {80, 443, 22, 53, 25, 445, 3389}

# Feature column order for normalization (must be numeric, not bool)
NUMERIC_FEATURE_COLUMNS = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "bytes_total",
    "bytes_ratio",
    "dst_port",
    "hour_of_day",
    "day_of_week",
    "unique_destinations",
    "unique_ports",
    "dns_queries_count",
    "nxdomain_ratio",
    "avg_dns_query_length",
]

# Bool features converted to 0/1 for normalization
BOOL_FEATURE_COLUMNS = ["is_common_port", "is_weekend"]

ALL_FEATURE_COLUMNS = NUMERIC_FEATURE_COLUMNS + BOOL_FEATURE_COLUMNS


def _is_common_port(port: int, common_ports: set[int] | None = None) -> bool:
    """Check if a port is in the common ports set."""
    ports = common_ports or DEFAULT_COMMON_PORTS
    return port in ports


def _compute_host_aggregates(
    conn_events: list[ZeekConn],
    dns_events: list[ZeekDNS],
) -> dict[str, dict[str, Any]]:
    """Compute per-host aggregate features.

    Returns a dict mapping src_ip to:
        unique_destinations, unique_ports, dns_queries_count,
        nxdomain_ratio, avg_dns_query_length
    """
    host_dsts: dict[str, set[str]] = defaultdict(set)
    host_ports: dict[str, set[int]] = defaultdict(set)
    host_dns_count: dict[str, int] = defaultdict(int)
    host_nxdomain_count: dict[str, int] = defaultdict(int)
    host_dns_query_lengths: dict[str, list[int]] = defaultdict(list)

    for conn in conn_events:
        host_dsts[conn.src_ip].add(conn.dst_ip)
        host_ports[conn.src_ip].add(conn.dst_port)

    for dns in dns_events:
        host_dns_count[dns.src_ip] += 1
        if dns.is_nxdomain:
            host_nxdomain_count[dns.src_ip] += 1
        host_dns_query_lengths[dns.src_ip].append(len(dns.query))

    result: dict[str, dict[str, Any]] = {}
    all_hosts = set(host_dsts.keys()) | set(host_dns_count.keys())
    for host in all_hosts:
        dns_count = host_dns_count.get(host, 0)
        nxdomain_count = host_nxdomain_count.get(host, 0)
        query_lengths = host_dns_query_lengths.get(host, [])
        result[host] = {
            "unique_destinations": len(host_dsts.get(host, set())),
            "unique_ports": len(host_ports.get(host, set())),
            "dns_queries_count": dns_count,
            "nxdomain_ratio": nxdomain_count / dns_count if dns_count > 0 else 0.0,
            "avg_dns_query_length": float(np.mean(query_lengths))
            if query_lengths
            else 0.0,
        }

    return result


def extract_event_features(
    conn_events: list[ZeekConn],
    dns_events: list[ZeekDNS] | None = None,
    http_events: list[ZeekHTTP] | None = None,
    ssl_events: list[ZeekSSL] | None = None,
    common_ports: set[int] | None = None,
) -> list[FeatureVector]:
    """Extract per-event feature vectors for Isolation Forest and Autoencoder.

    Each ZeekConn event becomes a FeatureVector with:
    - Connection features: duration, bytes, packets, bytes_ratio
    - Destination features: dst_port, is_common_port
    - Temporal features: hour_of_day, day_of_week, is_weekend
    - Host-aggregated features: unique_destinations, unique_ports, DNS stats

    Args:
        conn_events: List of Zeek connection events.
        dns_events: List of Zeek DNS events (for host aggregates).
        http_events: List of Zeek HTTP events (unused but accepted for API symmetry).
        ssl_events: List of Zeek SSL events (unused but accepted for API symmetry).
        common_ports: Set of common ports for is_common_port feature.

    Returns:
        List of FeatureVector objects.
    """
    dns_events = dns_events or []
    http_events = http_events or []
    ssl_events = ssl_events or []
    ports = common_ports or DEFAULT_COMMON_PORTS

    # Compute host-level aggregates
    host_aggs = _compute_host_aggregates(conn_events, dns_events)

    vectors: list[FeatureVector] = []
    for conn in conn_events:
        ts = conn.timestamp
        bytes_total = conn.bytes_total
        bytes_ratio = conn.orig_bytes / bytes_total if bytes_total > 0 else 0.0

        aggs = host_aggs.get(conn.src_ip, {})

        vector = FeatureVector(
            timestamp=ts,
            src_ip=conn.src_ip,
            dst_ip=conn.dst_ip,
            duration=conn.duration,
            orig_bytes=conn.orig_bytes,
            resp_bytes=conn.resp_bytes,
            orig_pkts=conn.orig_pkts,
            resp_pkts=conn.resp_pkts,
            bytes_total=bytes_total,
            bytes_ratio=bytes_ratio,
            dst_port=conn.dst_port,
            is_common_port=_is_common_port(conn.dst_port, ports),
            hour_of_day=float(ts.hour),
            day_of_week=float(ts.weekday()),
            is_weekend=ts.weekday() >= 5,
            unique_destinations=aggs.get("unique_destinations", 0),
            unique_ports=aggs.get("unique_ports", 0),
            dns_queries_count=aggs.get("dns_queries_count", 0),
            nxdomain_ratio=aggs.get("nxdomain_ratio", 0.0),
            avg_dns_query_length=aggs.get("avg_dns_query_length", 0.0),
        )
        vectors.append(vector)

    log.debug("event_features_extracted", count=len(vectors))
    return vectors


def extract_window_features(
    conn_events: list[ZeekConn],
    dns_events: list[ZeekDNS] | None = None,
    window_minutes: int = 5,
) -> list[WindowFeatures]:
    """Extract window-aggregated features for HMM.

    Groups events by src_ip and temporal window (default 5 minutes).
    Per window: bytes_out, bytes_in, pkts_total, unique_destinations,
    unique_ports, dns_queries, nxdomain_ratio, avg_duration, connection_count.

    Args:
        conn_events: List of Zeek connection events.
        dns_events: List of Zeek DNS events.
        window_minutes: Window size in minutes.

    Returns:
        List of WindowFeatures objects.
    """
    dns_events = dns_events or []
    window_delta = timedelta(minutes=window_minutes)

    if not conn_events:
        return []

    # Find the global time range
    all_ts = [c.timestamp for c in conn_events]
    min_ts = min(all_ts)

    # Group conn events by (src_ip, window)
    windows: dict[tuple[str, datetime], list[ZeekConn]] = defaultdict(list)
    for conn in conn_events:
        window_start = conn.timestamp - ((conn.timestamp - min_ts) % window_delta)
        key = (conn.src_ip, window_start)
        windows[key].append(conn)

    # Group DNS events by (src_ip, window)
    dns_windows: dict[tuple[str, datetime], list[ZeekDNS]] = defaultdict(list)
    for dns in dns_events:
        window_start = dns.timestamp - ((dns.timestamp - min_ts) % window_delta)
        key = (dns.src_ip, window_start)
        dns_windows[key].append(dns)

    results: list[WindowFeatures] = []
    for (src_ip, window_start), conns in windows.items():
        window_end = window_start + window_delta
        bytes_out = sum(c.orig_bytes for c in conns)
        bytes_in = sum(c.resp_bytes for c in conns)
        pkts_total = sum(c.pkts_total for c in conns)
        unique_dsts = {c.dst_ip for c in conns}
        unique_ports = {c.dst_port for c in conns}
        avg_duration = float(np.mean([c.duration for c in conns])) if conns else 0.0

        dns_list = dns_windows.get((src_ip, window_start), [])
        dns_queries = len(dns_list)
        nxdomain_count = sum(1 for d in dns_list if d.is_nxdomain)
        nxdomain_ratio = nxdomain_count / dns_queries if dns_queries > 0 else 0.0

        results.append(
            WindowFeatures(
                timestamp=window_start,
                src_ip=src_ip,
                window_start=window_start,
                window_end=window_end,
                bytes_out=bytes_out,
                bytes_in=bytes_in,
                pkts_total=pkts_total,
                unique_destinations=len(unique_dsts),
                unique_ports=len(unique_ports),
                dns_queries=dns_queries,
                nxdomain_ratio=nxdomain_ratio,
                avg_duration=avg_duration,
                connection_count=len(conns),
            )
        )

    # Sort by timestamp then src_ip for deterministic ordering
    results.sort(key=lambda w: (w.window_start, w.src_ip))
    log.debug("window_features_extracted", count=len(results))
    return results


def _vector_to_array(vector: FeatureVector) -> np.ndarray:
    """Convert a FeatureVector to a numpy array for normalization."""
    values: list[float] = []
    for col in NUMERIC_FEATURE_COLUMNS:
        values.append(float(getattr(vector, col)))
    for col in BOOL_FEATURE_COLUMNS:
        values.append(1.0 if getattr(vector, col) else 0.0)
    return np.array(values, dtype=np.float64)


def normalize_features(
    vectors: list[FeatureVector],
    scaler: StandardScaler | None = None,
) -> tuple[list[FeatureVector], StandardScaler]:
    """Normalize feature vectors using StandardScaler.

    Fills the ``normalized`` field of each FeatureVector with the scaled values.

    Args:
        vectors: List of FeatureVector objects to normalize.
        scaler: Optional pre-fitted scaler for inference. If None, a new
            scaler is fitted on the input vectors.

    Returns:
        Tuple of (list of FeatureVector with normalized filled, fitted scaler).
    """
    if not vectors:
        return vectors, StandardScaler() if scaler is None else scaler

    # Build feature matrix
    X = np.array([_vector_to_array(v) for v in vectors])

    if scaler is None:
        scaler = StandardScaler()
        scaler.fit(X)

    X_normalized = scaler.transform(X)

    # Fill normalized field
    for vector, row in zip(vectors, X_normalized):
        vector.normalized = [float(x) for x in row]

    log.debug(
        "features_normalized",
        count=len(vectors),
        n_features=X.shape[1],
    )
    return vectors, scaler


def get_feature_matrix(vectors: list[FeatureVector]) -> np.ndarray:
    """Get the normalized feature matrix from a list of FeatureVectors.

    If normalized field is empty, uses raw values instead.

    Args:
        vectors: List of FeatureVector objects.

    Returns:
        numpy array of shape (n_samples, n_features).
    """
    if not vectors:
        return np.array([]).reshape(0, len(ALL_FEATURE_COLUMNS))

    # Use normalized if available, otherwise raw
    if vectors[0].normalized:
        return np.array([v.normalized for v in vectors])
    else:
        return np.array([_vector_to_array(v) for v in vectors])
