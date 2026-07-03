"""Shared test fixtures for KhaiNet Brain tests.

All external dependencies (Kafka, LLM, Redis, MISP, ClickHouse, OpenSearch, Shuffle)
are mocked so tests run without real infrastructure.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest


# ---------------------------------------------------------------------------
# Alert fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def now_utc() -> datetime:
    return datetime(2026, 7, 3, 10, 15, 30, tzinfo=timezone.utc)


@pytest.fixture
def sample_alert_data(now_utc: datetime) -> dict[str, Any]:
    """Raw alert dict matching the input contract."""
    return {
        "alert_id": str(uuid4()),
        "timestamp": now_utc.isoformat().replace("+00:00", "Z"),
        "source": "ml-isolation-forest",
        "source_type": "anomaly",
        "severity_raw": 75,
        "confidence": 0.85,
        "src_ip": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "dst_ip": "f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "tcp",
        "service": "ssl",
        "bytes": 1048576,
        "packets": 1024,
        "duration": 30.5,
        "ml_model": "isolation-forest",
        "ml_score": 0.92,
        "ml_features": {
            "bytes_out": 900000,
            "bytes_in": 148576,
            "destinations_unique": 1,
            "dns_queries": 0,
            "hour_of_day": 10,
            "day_of_week": 4,
        },
        "rule_id": None,
        "rule_message": None,
        "event_type": "exfiltration",
        "tags": ["high-bytes-out", "rare-destination"],
        "raw_event": {"hostname": "SRV-DB-01"},
    }


@pytest.fixture
def sample_alert(sample_alert_data: dict[str, Any]):
    from src.models import Alert

    return Alert(**sample_alert_data)


@pytest.fixture
def low_severity_alert_data(now_utc: datetime) -> dict[str, Any]:
    """Low severity alert that should be filtered pre-LLM."""
    return {
        "alert_id": str(uuid4()),
        "timestamp": now_utc.isoformat().replace("+00:00", "Z"),
        "source": "suricata",
        "source_type": "signature",
        "severity_raw": 25,
        "confidence": 0.5,
        "src_ip": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
        "dst_ip": "def456def456def456def456def456def456def456def456def456def456def4",
        "protocol": "tcp",
        "event_type": "scan",
        "tags": [],
    }


@pytest.fixture
def backup_alert_data(now_utc: datetime) -> dict[str, Any]:
    """Alert matching a known FP rule (nightly backup)."""
    backup_time = now_utc.replace(hour=3)
    return {
        "alert_id": str(uuid4()),
        "timestamp": backup_time.isoformat().replace("+00:00", "Z"),
        "source": "ml-isolation-forest",
        "source_type": "anomaly",
        "severity_raw": 70,
        "confidence": 0.8,
        "src_ip": "aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
        "dst_ip": "bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2",
        "protocol": "tcp",
        "event_type": "exfiltration",
        "tags": ["backup", "scheduled"],
    }


@pytest.fixture
def three_correlated_alerts(now_utc: datetime) -> list[dict[str, Any]]:
    """Three alerts in a 5-min window for the same src_ip (scan→anomaly→exfil)."""
    base_ip = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    dst_ip = "f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8d9c0b1a2f7e8"
    return [
        {
            "alert_id": str(uuid4()),
            "timestamp": now_utc.isoformat().replace("+00:00", "Z"),
            "source": "suricata",
            "source_type": "signature",
            "severity_raw": 60,
            "confidence": 0.9,
            "src_ip": base_ip,
            "dst_ip": dst_ip,
            "protocol": "tcp",
            "event_type": "scan",
            "raw_event": {"hostname": "SRV-DB-01"},
        },
        {
            "alert_id": str(uuid4()),
            "timestamp": (now_utc + timedelta(minutes=2))
            .isoformat()
            .replace("+00:00", "Z"),
            "source": "ml-autoencoder",
            "source_type": "anomaly",
            "severity_raw": 68,
            "confidence": 0.82,
            "src_ip": base_ip,
            "dst_ip": dst_ip,
            "protocol": "tcp",
            "event_type": "anomaly",
            "raw_event": {"hostname": "SRV-DB-01"},
        },
        {
            "alert_id": str(uuid4()),
            "timestamp": (now_utc + timedelta(minutes=4))
            .isoformat()
            .replace("+00:00", "Z"),
            "source": "ml-hmm",
            "source_type": "anomaly",
            "severity_raw": 80,
            "confidence": 0.88,
            "src_ip": base_ip,
            "dst_ip": dst_ip,
            "protocol": "tcp",
            "event_type": "exfiltration",
            "raw_event": {"hostname": "SRV-DB-01"},
        },
    ]


# ---------------------------------------------------------------------------
# Enrichment fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_enrichment_data() -> dict[str, Any]:
    return {
        "asset_info": {
            "hostname": "SRV-DB-01",
            "type": "server",
            "criticality": 5,
            "os": "Linux",
            "services": ["postgresql", "ssh"],
            "owner": "DBA Team",
        },
        "geoip": {
            "dst_country": "RU",
            "dst_city": "Unknown",
            "dst_asn": "AS12345",
            "dst_asn_org": "Unknown ISP",
        },
        "threat_intel": {
            "dst_ip_malicious": True,
            "dst_ip_tags": ["c2-server", "botnet"],
            "source": "MISP",
        },
        "historical_context": {
            "first_seen_dst": "2026-07-03T10:15:00Z",
            "baseline_bytes_out_p99": 50000,
            "actual_bytes_out": 900000,
            "deviation_factor": 18.0,
        },
    }


# ---------------------------------------------------------------------------
# LLM output fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_llm_output() -> dict[str, Any]:
    """Valid LLM output that passes schema + hallucination validation."""
    return {
        "title": "Posible exfiltración desde SRV-DB-01 hacia IP externa",
        "description": "El servidor SRV-DB-01 realizó transferencia de 900KB hacia IP externa.",
        "explanation": "Tres señales convergen: volumen atípico, destino raro, transición de estado.",
        "correlation_reason": "Las 3 alertas comparten la misma IP origen y ventana temporal.",
        "false_positive_assessment": "Descartado como FP: volumen supera p99 del baseline.",
        "severity_adjustment": 5,
        "confidence": 0.88,
        "recommended_actions": [
            {
                "action": "notify_soc",
                "target": "soc-team",
                "priority": "immediate",
                "auto_execute": True,
                "justification": "Severidad crítica requiere notificación inmediata",
            },
            {
                "action": "isolate_host",
                "target": "SRV-DB-01",
                "priority": "high",
                "auto_execute": False,
                "justification": "Aislamiento requiere aprobación humana",
            },
        ],
    }


@pytest.fixture
def hallucinated_llm_output() -> dict[str, Any]:
    """LLM output with invented IPs (hallucination)."""
    return {
        "title": "Exfiltración detectada",
        "description": "El servidor envió datos a 192.168.99.99 desde 10.0.0.99.",
        "explanation": "Se detectó tráfico anómalo hacia 192.168.99.99.",
        "correlation_reason": "Mismo origen y destino.",
        "false_positive_assessment": "No es FP.",
        "severity_adjustment": 0,
        "confidence": 0.9,
        "recommended_actions": [],
    }


# ---------------------------------------------------------------------------
# Mock client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_redis():
    """Mock Redis client for session manager and semantic cache."""
    from unittest.mock import AsyncMock, MagicMock

    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.keys = AsyncMock(return_value=[])
    redis.lpush = AsyncMock(return_value=1)
    redis.lrange = AsyncMock(return_value=[])
    return redis


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.AsyncClient for LLM and Shuffle."""
    from unittest.mock import AsyncMock, MagicMock

    client = MagicMock()
    client.is_closed = False
    client.post = AsyncMock()
    client.aclose = AsyncMock()
    return client


@pytest.fixture
def mock_llm_response(valid_llm_output: dict[str, Any]):
    """Mock LLM API response (OpenAI-compatible chat completion)."""
    from unittest.mock import MagicMock

    response = MagicMock()
    response.status_code = 200
    response.content = b'{"data": "response"}'
    response.json.return_value = {
        "choices": [
            {"message": {"content": __import__("json").dumps(valid_llm_output)}}
        ]
    }
    response.raise_for_status = MagicMock()
    return response


@pytest.fixture
def mock_shuffle_response():
    """Mock Shuffle webhook response."""
    from unittest.mock import MagicMock

    response = MagicMock()
    response.status_code = 200
    response.content = b'{"status": "ok"}'
    response.json.return_value = {"status": "ok", "execution_id": "exec-123"}
    response.raise_for_status = MagicMock()
    return response


@pytest.fixture
def mock_opensearch_client():
    """Mock OpenSearch client for asset lookup."""
    from unittest.mock import MagicMock

    client = MagicMock()
    client.search = MagicMock(
        return_value={
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "hostname": "SRV-DB-01",
                            "type": "server",
                            "criticality": 5,
                            "os": "Linux",
                            "services": ["postgresql", "ssh"],
                            "owner": "DBA Team",
                        }
                    }
                ]
            }
        }
    )
    return client


@pytest.fixture
def mock_misp_client():
    """Mock PyMISP client for threat intel."""
    from unittest.mock import MagicMock

    client = MagicMock()

    # Mock search result with tags
    attr = MagicMock()
    tag1 = MagicMock()
    tag1.name = "c2-server"
    tag2 = MagicMock()
    tag2.name = "botnet"
    attr.tags = [tag1, tag2]

    client.search = MagicMock(return_value=[attr])
    return client


@pytest.fixture
def mock_clickhouse_client():
    """Mock ClickHouse client for historical baseline."""
    from unittest.mock import MagicMock

    client = MagicMock()
    result = MagicMock()
    result.result_rows = [["f7e8d9c0b1a2", "2026-07-03T10:15:00Z", 50000, 900000]]
    client.query = MagicMock(return_value=result)
    return client


@pytest.fixture
def mock_geoip_reader():
    """Mock GeoIP reader."""
    from unittest.mock import MagicMock

    reader = MagicMock()
    response = MagicMock()
    response.country.iso_code = "RU"
    response.city.name = "Moscow"
    response.autonomous_system_number = 12345
    response.autonomous_system_organization = "Unknown ISP"
    reader.city = MagicMock(return_value=response)
    return reader


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def test_config() -> dict[str, Any]:
    """Test configuration with short timeouts for fast tests."""
    return {
        "kafka": {
            "bootstrap_servers": "localhost:9092",
            "group_id": "brain-test",
            "input_topics": ["ml-scores", "suricata-alerts", "wazuh-events"],
            "output_topic": "brain-incidents",
            "dlq_topic": "brain-dlq",
        },
        "llm": {
            "base_url": "http://localhost:8080",
            "model": "brain-kh7-v1-test",
            "timeout_seconds": 5,
            "max_tokens": 2000,
            "temperature": 0.1,
            "retry": {"max_attempts": 2, "wait_min": 0.1, "wait_max": 1},
            "circuit_breaker": {
                "failure_threshold": 3,
                "recovery_timeout": 2,
                "half_open_max_calls": 2,
            },
            "semantic_cache": {"ttl_seconds": 60},
        },
        "redis": {
            "url": "redis://localhost:6379/0",
            "session_timeout_seconds": 1800,
        },
        "correlation": {
            "window_seconds": 300,
            "min_alerts_for_group": 2,
        },
        "enrichment": {
            "timeout_seconds": 5,
        },
        "shuffle": {
            "url": "http://localhost:3001",
            "api_key": "test-key",
            "webhook_path": "/api/v1/workflows/brain-incident/executions",
            "timeout_seconds": 5,
        },
        "scoring": {
            "weights": {
                "model_severity": 0.40,
                "asset_criticality": 0.25,
                "threat_intel": 0.15,
                "historical": 0.10,
                "correlation": 0.10,
            },
            "default_asset_criticality": 2,
            "bonus": {
                "threat_intel_critical_threshold": 100,
                "asset_criticality_threshold": 80,
                "correlation_strong_threshold": 100,
                "model_severity_high_threshold": 70,
            },
        },
        "logging": {"level": "INFO", "format": "json"},
        "prometheus": {"port": 9091},
    }


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------


@pytest.fixture
def event_loop():
    """Create an event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
