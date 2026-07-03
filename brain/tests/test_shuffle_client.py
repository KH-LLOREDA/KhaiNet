"""Tests for the Shuffle SOAR client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.models import Incident, IncidentStatus, SeverityLabel
from src.shuffle_client import ShuffleClient


@pytest.fixture
def critical_incident(three_correlated_alerts, sample_enrichment_data):
    from src.models import Alert, EnrichmentData, IncidentEntities, IncidentMetrics

    alerts = [Alert(**a) for a in three_correlated_alerts]
    return Incident(
        severity=85,
        severity_label=SeverityLabel.CRITICAL,
        confidence=0.88,
        title="Test critical incident",
        description="Test description",
        correlation_reason="Test reason",
        false_positive_assessment="Not FP",
        alerts=alerts,
        entities=IncidentEntities(src_ips=["abc"], dst_ips=["def"]),
        enrichment=EnrichmentData(**sample_enrichment_data),
        xai_available=True,
        llm_model="test",
        llm_latency_ms=100,
    )


@pytest.mark.asyncio
async def test_shuffle_send_incident_success(
    test_config, critical_incident, mock_shuffle_response
):
    """Test case 9: critical incident triggers Shuffle webhook."""
    client = ShuffleClient(test_config["shuffle"])

    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(return_value=mock_shuffle_response)
    client._http_client = mock_http

    result = await client.send_incident(critical_incident)

    assert result["status"] == "ok"
    mock_http.post.assert_called_once()

    # Check the URL contains the critical playbook
    call_args = mock_http.post.call_args
    url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
    assert "brain-critical-response" in str(url)


@pytest.mark.asyncio
async def test_shuffle_timeout(test_config, critical_incident):
    """Shuffle timeout returns error dict."""
    client = ShuffleClient(test_config["shuffle"])

    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    client._http_client = mock_http

    result = await client.send_incident(critical_incident)
    assert result["error"] == "timeout"


@pytest.mark.asyncio
async def test_shuffle_connection_error(test_config, critical_incident):
    """Shuffle connection error returns error dict."""
    client = ShuffleClient(test_config["shuffle"])

    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
    client._http_client = mock_http

    result = await client.send_incident(critical_incident)
    assert result["error"] == "connection_error"


@pytest.mark.asyncio
async def test_shuffle_payload_structure(
    test_config, critical_incident, mock_shuffle_response
):
    """Shuffle payload contains incident, playbook, and actions."""
    client = ShuffleClient(test_config["shuffle"])

    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(return_value=mock_shuffle_response)
    client._http_client = mock_http

    await client.send_incident(critical_incident)

    call_args = mock_http.post.call_args
    payload = call_args[1]["json"]
    assert "incident" in payload
    assert "playbook" in payload
    assert payload["playbook"] == "brain-critical-response"
    assert "auto_execute_actions" in payload
    assert "manual_review_actions" in payload
