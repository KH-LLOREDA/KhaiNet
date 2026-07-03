"""Shared test fixtures for KhaiNet detection tests.

All tests use synthetic data generators with fixed seeds for reproducibility.
No real infrastructure (Zeek, OpenSearch) is required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

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
)
from src.synthetic_data import _pseudonymize_ip


# ---------------------------------------------------------------------------
# Time fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def now_utc() -> datetime:
    return datetime(2026, 7, 3, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def base_time() -> datetime:
    return datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# IP fixtures (pseudonymized hashes)
# ---------------------------------------------------------------------------


@pytest.fixture
def src_ip_a() -> str:
    return _pseudonymize_ip("10.0.0.1")


@pytest.fixture
def src_ip_b() -> str:
    return _pseudonymize_ip("10.0.0.2")


@pytest.fixture
def dst_ip_a() -> str:
    return _pseudonymize_ip("192.168.1.1")


@pytest.fixture
def dst_ip_b() -> str:
    return _pseudonymize_ip("192.168.1.2")


# ---------------------------------------------------------------------------
# ZeekConn fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_conn(now_utc, src_ip_a, dst_ip_a) -> ZeekConn:
    return ZeekConn(
        timestamp=now_utc,
        uid="abc123def456",
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        duration=1.5,
        orig_bytes=5000,
        resp_bytes=50000,
        orig_pkts=10,
        resp_pkts=20,
        service="ssl",
        conn_state="SF",
    )


@pytest.fixture
def sample_conn_events(
    base_time, src_ip_a, src_ip_b, dst_ip_a, dst_ip_b
) -> list[ZeekConn]:
    """20 conn events: 18 normal + 2 anomalous."""
    events: list[ZeekConn] = []
    for i in range(18):
        events.append(
            ZeekConn(
                timestamp=base_time + timedelta(seconds=i * 30),
                uid=f"uid-norm-{i}",
                src_ip=src_ip_a if i % 2 == 0 else src_ip_b,
                dst_ip=dst_ip_a if i % 2 == 0 else dst_ip_b,
                src_port=50000 + i,
                dst_port=443 if i % 2 == 0 else 80,
                protocol="tcp",
                duration=round(0.5 + i * 0.1, 6),
                orig_bytes=1000 + i * 100,
                resp_bytes=5000 + i * 200,
                orig_pkts=5 + i,
                resp_pkts=10 + i,
                service="ssl" if i % 2 == 0 else "http",
                conn_state="SF",
            )
        )
    # Anomaly 1: exfiltration (high bytes)
    events.append(
        ZeekConn(
            timestamp=base_time + timedelta(seconds=600),
            uid="uid-anom-exfil",
            src_ip=src_ip_a,
            dst_ip=dst_ip_b,
            src_port=55000,
            dst_port=443,
            protocol="tcp",
            duration=300.0,
            orig_bytes=50_000_000,
            resp_bytes=100,
            orig_pkts=50000,
            resp_pkts=10,
            service="ssl",
            conn_state="SF",
        )
    )
    # Anomaly 2: scan (many destinations, short connections)
    events.append(
        ZeekConn(
            timestamp=base_time + timedelta(seconds=630),
            uid="uid-anom-scan",
            src_ip=src_ip_b,
            dst_ip=_pseudonymize_ip("192.168.99.99"),
            src_port=56000,
            dst_port=22,
            protocol="tcp",
            duration=0.01,
            orig_bytes=50,
            resp_bytes=0,
            orig_pkts=1,
            resp_pkts=0,
            service=None,
            conn_state="S0",
        )
    )
    return events


# ---------------------------------------------------------------------------
# ZeekDNS fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_dns(now_utc, src_ip_a, dst_ip_a) -> ZeekDNS:
    return ZeekDNS(
        timestamp=now_utc,
        uid="dns123def456",
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        src_port=54321,
        dst_port=53,
        protocol="udp",
        query="example.com",
        qclass=1,
        qtype="A",
        rcode="NOERROR",
        rcode_name="NOERROR",
        answers=["10.0.0.1"],
        ttl=[300],
    )


@pytest.fixture
def sample_dns_events(base_time, src_ip_a, src_ip_b, dst_ip_a) -> list[ZeekDNS]:
    """10 DNS events: 8 normal + 2 NXDOMAIN."""
    events: list[ZeekDNS] = []
    for i in range(8):
        events.append(
            ZeekDNS(
                timestamp=base_time + timedelta(seconds=i * 60),
                uid=f"uid-dns-norm-{i}",
                src_ip=src_ip_a if i % 2 == 0 else src_ip_b,
                dst_ip=dst_ip_a,
                src_port=50000 + i,
                dst_port=53,
                protocol="udp",
                query=f"host{i}.example.com",
                qclass=1,
                qtype="A",
                rcode="NOERROR",
                rcode_name="NOERROR",
                answers=[f"10.0.0.{i}"],
                ttl=[300],
            )
        )
    # NXDOMAIN anomalies
    for i in range(2):
        events.append(
            ZeekDNS(
                timestamp=base_time + timedelta(seconds=500 + i * 10),
                uid=f"uid-dns-nxdomain-{i}",
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                src_port=55000 + i,
                dst_port=53,
                protocol="udp",
                query="nonexistent.evil.com",
                qclass=1,
                qtype="A",
                rcode="NXDOMAIN",
                rcode_name="NXDOMAIN",
                answers=[],
                ttl=[],
            )
        )
    return events


# ---------------------------------------------------------------------------
# ZeekHTTP fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_http(now_utc, src_ip_a, dst_ip_a) -> ZeekHTTP:
    return ZeekHTTP(
        timestamp=now_utc,
        uid="http123def456",
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        src_port=54321,
        dst_port=80,
        method="GET",
        host="example.com",
        uri="/index.html",
        user_agent="Mozilla/5.0",
        status_code=200,
        request_body_len=0,
        response_body_len=5000,
    )


@pytest.fixture
def sample_http_events(base_time, src_ip_a, dst_ip_a) -> list[ZeekHTTP]:
    """5 HTTP events."""
    events: list[ZeekHTTP] = []
    for i in range(5):
        events.append(
            ZeekHTTP(
                timestamp=base_time + timedelta(seconds=i * 60),
                uid=f"uid-http-{i}",
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                src_port=50000 + i,
                dst_port=80,
                method="GET" if i % 2 == 0 else "POST",
                host="example.com",
                uri=f"/page{i}",
                user_agent="Mozilla/5.0",
                status_code=200,
                request_body_len=i * 100,
                response_body_len=5000 + i * 1000,
            )
        )
    return events


# ---------------------------------------------------------------------------
# ZeekSSL fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_ssl(now_utc, src_ip_a, dst_ip_a) -> ZeekSSL:
    return ZeekSSL(
        timestamp=now_utc,
        uid="ssl123def456",
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        src_port=54321,
        dst_port=443,
        version="TLSv1.2",
        cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        server_name="example.com",
        resumed=False,
        subject="CN=example.com",
        issuer="CN=Let's Encrypt Authority X3",
    )


@pytest.fixture
def sample_ssl_events(base_time, src_ip_a, dst_ip_a) -> list[ZeekSSL]:
    """3 SSL events."""
    events: list[ZeekSSL] = []
    for i in range(3):
        events.append(
            ZeekSSL(
                timestamp=base_time + timedelta(seconds=i * 60),
                uid=f"uid-ssl-{i}",
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                src_port=50000 + i,
                dst_port=443,
                version="TLSv1.2",
                cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                server_name=f"host{i}.example.com",
                resumed=False,
                subject=f"CN=host{i}.example.com",
                issuer="CN=Let's Encrypt Authority X3",
            )
        )
    return events


# ---------------------------------------------------------------------------
# FeatureVector fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_feature_vector(now_utc, src_ip_a, dst_ip_a) -> FeatureVector:
    return FeatureVector(
        timestamp=now_utc,
        src_ip=src_ip_a,
        dst_ip=dst_ip_a,
        duration=1.5,
        orig_bytes=5000,
        resp_bytes=50000,
        orig_pkts=10,
        resp_pkts=20,
        bytes_total=55000,
        bytes_ratio=5000 / 55000,
        dst_port=443,
        is_common_port=True,
        hour_of_day=10.0,
        day_of_week=4.0,
        is_weekend=False,
        unique_destinations=5,
        unique_ports=3,
        dns_queries_count=10,
        nxdomain_ratio=0.1,
        avg_dns_query_length=15.0,
    )


@pytest.fixture
def sample_feature_vectors(base_time, src_ip_a, dst_ip_a) -> list[FeatureVector]:
    """20 feature vectors for testing."""
    vectors: list[FeatureVector] = []
    for i in range(20):
        vectors.append(
            FeatureVector(
                timestamp=base_time + timedelta(seconds=i * 60),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                duration=1.0 + i * 0.1,
                orig_bytes=1000 + i * 100,
                resp_bytes=5000 + i * 200,
                orig_pkts=5 + i,
                resp_pkts=10 + i,
                bytes_total=6000 + i * 300,
                bytes_ratio=(1000 + i * 100) / (6000 + i * 300),
                dst_port=443,
                is_common_port=True,
                hour_of_day=float(i % 24),
                day_of_week=float(i % 7),
                is_weekend=(i % 7) >= 5,
                unique_destinations=3 + (i % 5),
                unique_ports=2 + (i % 3),
                dns_queries_count=i,
                nxdomain_ratio=0.0,
                avg_dns_query_length=10.0 + i,
            )
        )
    return vectors


# ---------------------------------------------------------------------------
# WindowFeatures fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_window_features(base_time, src_ip_a) -> list[WindowFeatures]:
    """10 window features for HMM testing."""
    windows: list[WindowFeatures] = []
    for i in range(10):
        ws = base_time + timedelta(minutes=i * 5)
        windows.append(
            WindowFeatures(
                timestamp=ws,
                src_ip=src_ip_a,
                window_start=ws,
                window_end=ws + timedelta(minutes=5),
                bytes_out=10000 + i * 1000,
                bytes_in=50000 + i * 2000,
                pkts_total=100 + i * 10,
                unique_destinations=3 + (i % 4),
                unique_ports=2 + (i % 3),
                dns_queries=5 + i,
                nxdomain_ratio=0.0,
                avg_duration=1.0 + i * 0.1,
                connection_count=10 + i,
            )
        )
    return windows


# ---------------------------------------------------------------------------
# ModelResult fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_model_result(now_utc, src_ip_a) -> ModelResult:
    return ModelResult(
        model_name="isolation_forest",
        event_id="evt-001",
        timestamp=now_utc,
        src_ip=src_ip_a,
        score=0.85,
        is_anomaly=True,
        threshold=0.7,
        details={"raw_score": -0.5},
    )


# ---------------------------------------------------------------------------
# BaselineStats fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_baseline_stats(src_ip_a) -> BaselineStats:
    return BaselineStats(
        src_ip=src_ip_a,
        service="ssl",
        metric="bytes_out",
        mean=5000.0,
        std=2000.0,
        min_val=100.0,
        max_val=20000.0,
        p50=4500.0,
        p95=15000.0,
        p99=19000.0,
        sample_count=100,
        window_hours=24,
    )


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Test configuration matching detection_config.yaml."""
    return {
        "zeek": {
            "log_dir": "/var/log/zeek",
            "pseudonymize_ips": True,
            "salt": "khainet-salt",
        },
        "feature_engineering": {
            "window_minutes": 5,
            "common_ports": [80, 443, 22, 53, 25, 445, 3389],
            "normalization": "standard",
        },
        "isolation_forest": {
            "n_estimators": 50,
            "contamination": "auto",
            "random_state": 42,
            "threshold": 0.7,
        },
        "autoencoder": {
            "hidden_dims": [32, 16, 8],
            "learning_rate": 0.01,
            "epochs": 20,
            "batch_size": 16,
            "threshold_percentile": 99,
            "random_state": 42,
        },
        "hmm": {
            "n_components": 4,
            "n_iter": 50,
            "covariance_type": "diag",
            "random_state": 42,
            "state_labels": ["normal", "scan", "exfil", "c2"],
        },
        "baseline": {
            "window_hours": 24,
            "metrics": [
                "bytes_out",
                "bytes_in",
                "duration",
                "unique_destinations",
                "unique_ports",
                "pkts_total",
                "dns_queries",
            ],
        },
        "orchestrator": {
            "model_dir": "./models",
            "mock_mode": True,
        },
    }


# ---------------------------------------------------------------------------
# Small config for fast tests
# ---------------------------------------------------------------------------


@pytest.fixture
def fast_config() -> dict[str, Any]:
    """Minimal config for fast test execution."""
    return {
        "isolation_forest": {
            "n_estimators": 10,
            "contamination": "auto",
            "random_state": 42,
            "threshold": 0.6,
        },
        "autoencoder": {
            "hidden_dims": [16, 8],
            "learning_rate": 0.01,
            "epochs": 10,
            "batch_size": 8,
            "threshold_percentile": 99,
            "random_state": 42,
        },
        "hmm": {
            "n_components": 4,
            "n_iter": 20,
            "covariance_type": "diag",
            "random_state": 42,
        },
        "baseline": {
            "window_hours": 24,
        },
        "feature_engineering": {
            "window_minutes": 5,
        },
        "orchestrator": {
            "mock_mode": True,
        },
    }
