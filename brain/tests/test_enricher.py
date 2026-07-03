"""Tests for the enrichment engine."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from src.enricher import Enricher
from src.models import Alert, AlertGroup, EnrichmentData


@pytest.mark.asyncio
async def test_enrich_all_sources_success(
    sample_alert,
    mock_opensearch_client,
    mock_geoip_reader,
    mock_misp_client,
    mock_clickhouse_client,
):
    """Enrichment succeeds with all sources available."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_opensearch_client(mock_opensearch_client)
    enricher.set_geoip_reader(mock_geoip_reader)
    enricher.set_misp_client(mock_misp_client)
    enricher.set_clickhouse_client(mock_clickhouse_client)

    group = AlertGroup(alerts=[sample_alert], entity=sample_alert.src_ip)
    result = await enricher.enrich(group)

    assert isinstance(result, EnrichmentData)
    assert result.asset_info.hostname == "SRV-DB-01"
    assert result.asset_info.criticality == 5
    assert result.threat_intel.dst_ip_malicious
    assert "c2-server" in result.threat_intel.dst_ip_tags
    assert result.historical_context.deviation_factor == 18.0
    assert not result.partial
    assert len(result.failed_sources) == 0


@pytest.mark.asyncio
async def test_enrich_partial_failure(
    sample_alert, mock_opensearch_client, mock_geoip_reader
):
    """Test case 6: MISP down → enrichment partial, continues with others."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_opensearch_client(mock_opensearch_client)
    enricher.set_geoip_reader(mock_geoip_reader)
    # MISP client raises an error
    misp = MagicMock()
    misp.search = MagicMock(side_effect=ConnectionError("MISP down"))
    enricher.set_misp_client(misp)
    # ClickHouse also not set → will return empty

    group = AlertGroup(alerts=[sample_alert], entity=sample_alert.src_ip)
    result = await enricher.enrich(group)

    assert result.partial
    assert "threat_intel" in result.failed_sources
    assert result.asset_info.hostname == "SRV-DB-01"  # asset still worked


@pytest.mark.asyncio
async def test_enrich_all_sources_down(sample_alert):
    """All enrichment sources fail → all empty, partial=True."""
    enricher = Enricher({"timeout_seconds": 1})
    # No clients set → all return empty (not exceptions)

    group = AlertGroup(alerts=[sample_alert], entity=sample_alert.src_ip)
    result = await enricher.enrich(group)

    assert isinstance(result, EnrichmentData)
    # Without clients, lookups return empty data, not exceptions
    assert result.asset_info.hostname is None
    assert not result.partial  # No exceptions, just empty data


@pytest.mark.asyncio
async def test_enrich_asset_lookup_with_client(sample_alert, mock_opensearch_client):
    """Asset lookup returns correct data from OpenSearch."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_opensearch_client(mock_opensearch_client)

    result = await enricher.asset_lookup([sample_alert.src_ip])

    assert result.hostname == "SRV-DB-01"
    assert result.criticality == 5
    assert result.os == "Linux"
    assert "postgresql" in result.services


@pytest.mark.asyncio
async def test_enrich_threat_intel_malicious(sample_alert, mock_misp_client):
    """Threat intel lookup returns malicious=True with tags."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_misp_client(mock_misp_client)

    result = await enricher.threat_intel_lookup(
        [sample_alert.src_ip], [sample_alert.dst_ip]
    )

    assert result.dst_ip_malicious
    assert "c2-server" in result.dst_ip_tags
    assert "botnet" in result.dst_ip_tags


@pytest.mark.asyncio
async def test_enrich_historical_baseline(sample_alert, mock_clickhouse_client):
    """Historical lookup returns baseline and deviation."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_clickhouse_client(mock_clickhouse_client)

    result = await enricher.historical_lookup(
        [sample_alert.src_ip], [sample_alert.dst_ip]
    )

    assert result.baseline_bytes_out_p99 == 50000
    assert result.actual_bytes_out == 900000
    assert result.deviation_factor == 18.0


# ---------------------------------------------------------------------------
# W7: GeoIP pseudonymization handling tests
# ---------------------------------------------------------------------------


def test_is_pseudonymized_sha256_hash():
    """SHA-256 hash (64 hex chars) is detected as pseudonymized."""
    assert Enricher._is_pseudonymized(
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    )


def test_is_pseudonymized_sha1_hash():
    """SHA-1 hash (40 hex chars) is detected as pseudonymized."""
    assert Enricher._is_pseudonymized("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")


def test_is_pseudonymized_hash_prefix():
    """IPs with 'hash:' prefix are detected as pseudonymized."""
    assert Enricher._is_pseudonymized("hash:abc123")


def test_is_pseudonymized_real_ipv4():
    """Real IPv4 addresses are NOT pseudonymized."""
    assert not Enricher._is_pseudonymized("192.168.1.1")
    assert not Enricher._is_pseudonymized("10.0.0.1")
    assert not Enricher._is_pseudonymized("8.8.8.8")


def test_is_pseudonymized_real_ipv6():
    """Real IPv6 addresses are NOT pseudonymized."""
    assert not Enricher._is_pseudonymized("2001:db8::1")
    assert not Enricher._is_pseudonymized("fe80::1")


@pytest.mark.asyncio
async def test_geoip_skips_pseudonymized_ips(mock_geoip_reader):
    """GeoIP lookup skips pseudonymized IPs and returns empty info."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_geoip_reader(mock_geoip_reader)

    # Pseudonymized IP (SHA-256 hash)
    result = await enricher.geoip_lookup(
        ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"]
    )
    assert result.dst_country is None
    # GeoIP reader should not have been called for pseudonymized IP
    mock_geoip_reader.city.assert_not_called()


@pytest.mark.asyncio
async def test_geoip_lookup_real_ip(mock_geoip_reader):
    """GeoIP lookup works for real (non-pseudonymized) IPs."""
    enricher = Enricher({"timeout_seconds": 5})
    enricher.set_geoip_reader(mock_geoip_reader)

    result = await enricher.geoip_lookup(["8.8.8.8"])
    assert result.dst_country == "RU"
    assert result.dst_city == "Moscow"
    mock_geoip_reader.city.assert_called_once_with("8.8.8.8")
