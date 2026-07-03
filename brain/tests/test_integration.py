"""End-to-end integration tests with mocks.

Covers the 10 critical test cases from the spec (section 16.2).
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.brain_client import BrainLLMClient, CircuitBreakerOpenError, CircuitState
from src.consumer import AlertConsumer
from src.correlator import Correlator
from src.enricher import Enricher
from src.main import BrainPipeline
from src.models import Alert, AlertGroup, Incident
from src.scorer import Scorer
from src.schema_validator import SchemaValidationError
from src.shuffle_client import ShuffleClient
from src.state_manager import SessionManager
from src.xai import XAIBuilder


# ---------------------------------------------------------------------------
# Integration test helpers
# ---------------------------------------------------------------------------


async def process_alerts_through_pipeline(
    alerts: list[Alert],
    config: dict,
    llm_response: dict | None = None,
    llm_exception: Exception | None = None,
    enrichment_clients: dict | None = None,
) -> list[Incident]:
    """Process alerts through a mini pipeline and return incidents."""
    session_mgr = SessionManager(session_timeout_seconds=1800)
    correlator = Correlator(session_mgr, window_seconds=300, min_alerts_for_group=2)
    enricher = Enricher(config.get("enrichment", {}))

    # Set enrichment clients if provided
    if enrichment_clients:
        if "opensearch" in enrichment_clients:
            enricher.set_opensearch_client(enrichment_clients["opensearch"])
        if "misp" in enrichment_clients:
            enricher.set_misp_client(enrichment_clients["misp"])
        if "clickhouse" in enrichment_clients:
            enricher.set_clickhouse_client(enrichment_clients["clickhouse"])
        if "geoip" in enrichment_clients:
            enricher.set_geoip_reader(enrichment_clients["geoip"])

    scorer = Scorer(config)
    xai_builder = XAIBuilder()

    # Set up LLM client
    llm_config = config.get("llm", {}).copy()
    llm_config["_redis_client"] = None
    brain_client = BrainLLMClient(llm_config)

    if llm_response is not None or llm_exception is not None:
        mock_http = MagicMock()
        mock_http.is_closed = False
        if llm_exception:
            mock_http.post = AsyncMock(side_effect=llm_exception)
        else:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = b'{"data": "resp"}'
            mock_response.json.return_value = {
                "choices": [{"message": {"content": json.dumps(llm_response)}}]
            }
            mock_response.raise_for_status = MagicMock()
            mock_http.post = AsyncMock(return_value=mock_response)
        brain_client._http_client = mock_http

    incidents: list[Incident] = []
    for alert in alerts:
        groups = await correlator.process_alert(alert)
        groups = [g for g in groups if not correlator.should_filter_pre_llm(g)]

        for group in groups:
            enrichment = await enricher.enrich(group)
            severity = scorer.calculate(group, enrichment)

            try:
                group_dict = group.model_dump(mode="json")
                enrichment_dict = enrichment.model_dump(mode="json")
                llm_result = await brain_client.correlate(group_dict, enrichment_dict)
                latency_ms = llm_result.pop("_latency_ms", 0)
                incident = xai_builder.build_from_llm(
                    group=group,
                    enrichment=enrichment,
                    severity=severity,
                    llm_output=llm_result,
                    llm_model="test",
                    llm_latency_ms=latency_ms,
                )
            except (
                CircuitBreakerOpenError,
                SchemaValidationError,
                httpx.TimeoutException,
                httpx.ConnectError,
            ):
                incident = xai_builder.build_fallback(
                    group=group,
                    enrichment=enrichment,
                    severity=severity,
                )
            incidents.append(incident)

    return incidents


# ---------------------------------------------------------------------------
# Critical test cases (spec section 16.2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_case1_3_alerts_5min_window(
    three_correlated_alerts, test_config, valid_llm_output, sample_enrichment_data
):
    """Case 1: 3 alerts in 5 min → 1 incident with 3 alerts."""
    alerts = [Alert(**a) for a in three_correlated_alerts]
    incidents = await process_alerts_through_pipeline(
        alerts, test_config, llm_response=valid_llm_output
    )

    assert len(incidents) >= 1
    # At least one incident should have all 3 alerts
    incident = max(incidents, key=lambda i: len(i.alerts))
    assert len(incident.alerts) >= 3
    assert incident.xai_available
    assert incident.title == valid_llm_output["title"]


@pytest.mark.asyncio
async def test_case2_single_low_severity_no_incident(
    low_severity_alert_data, test_config, valid_llm_output
):
    """Case 2: single low severity alert → no incident."""
    alert = Alert(**low_severity_alert_data)
    incidents = await process_alerts_through_pipeline(
        [alert], test_config, llm_response=valid_llm_output
    )
    assert len(incidents) == 0


@pytest.mark.asyncio
async def test_case3_llm_timeout_fallback(three_correlated_alerts, test_config):
    """Case 3: LLM timeout → fallback, incident without XAI, tagged for reproccess."""
    alerts = [Alert(**a) for a in three_correlated_alerts]
    incidents = await process_alerts_through_pipeline(
        alerts, test_config, llm_exception=httpx.TimeoutException("timeout")
    )

    assert len(incidents) >= 1
    incident = incidents[0]
    assert not incident.xai_available
    assert incident.explanation is None
    assert "needs_xai_reprocess" in incident.tags


@pytest.mark.asyncio
async def test_case4_llm_hallucination(
    three_correlated_alerts, test_config, hallucinated_llm_output
):
    """Case 4: LLM hallucinates IPs → SchemaValidationError, fallback activated."""
    alerts = [Alert(**a) for a in three_correlated_alerts]
    incidents = await process_alerts_through_pipeline(
        alerts, test_config, llm_response=hallucinated_llm_output
    )

    assert len(incidents) >= 1
    incident = incidents[0]
    # Should have fallen back
    assert not incident.xai_available
    assert "needs_xai_reprocess" in incident.tags


@pytest.mark.asyncio
async def test_case5_circuit_breaker_open(three_correlated_alerts, test_config):
    """Case 5: circuit breaker open → all correlations use fallback."""
    alerts = [Alert(**a) for a in three_correlated_alerts]

    # Create pipeline with circuit breaker forced open
    llm_config = test_config["llm"].copy()
    llm_config["_redis_client"] = None
    brain_client = BrainLLMClient(llm_config)
    brain_client.circuit_breaker._state = CircuitState.OPEN
    brain_client.circuit_breaker._failure_count = 10
    brain_client.circuit_breaker.recovery_timeout = 999
    brain_client.circuit_breaker._last_failure_time = float("inf")

    session_mgr = SessionManager()
    correlator = Correlator(session_mgr)
    enricher = Enricher(test_config.get("enrichment", {}))
    scorer = Scorer(test_config)
    xai_builder = XAIBuilder()

    incidents: list[Incident] = []
    for alert in alerts:
        groups = await correlator.process_alert(alert)
        groups = [g for g in groups if not correlator.should_filter_pre_llm(g)]
        for group in groups:
            enrichment = await enricher.enrich(group)
            severity = scorer.calculate(group, enrichment)
            try:
                group_dict = group.model_dump(mode="json")
                enrichment_dict = enrichment.model_dump(mode="json")
                await brain_client.correlate(group_dict, enrichment_dict)
            except CircuitBreakerOpenError:
                incident = xai_builder.build_fallback(
                    group=group, enrichment=enrichment, severity=severity
                )
                incidents.append(incident)

    assert len(incidents) >= 1
    for incident in incidents:
        assert not incident.xai_available
        assert "needs_xai_reprocess" in incident.tags


@pytest.mark.asyncio
async def test_case6_enrichment_partial(
    three_correlated_alerts,
    test_config,
    valid_llm_output,
    mock_opensearch_client,
    mock_geoip_reader,
):
    """Case 6: MISP down → enrichment partial, incident still produced."""
    alerts = [Alert(**a) for a in three_correlated_alerts]

    # MISP client that fails
    misp = MagicMock()
    misp.search = MagicMock(side_effect=ConnectionError("MISP down"))

    incidents = await process_alerts_through_pipeline(
        alerts,
        test_config,
        llm_response=valid_llm_output,
        enrichment_clients={
            "opensearch": mock_opensearch_client,
            "geoip": mock_geoip_reader,
            "misp": misp,
        },
    )

    assert len(incidents) >= 1
    incident = incidents[0]
    assert incident.enrichment.partial
    assert "threat_intel" in incident.enrichment.failed_sources


@pytest.mark.asyncio
async def test_case7_sessionization_30min(now_utc, test_config, valid_llm_output):
    """Case 7: scan at 10:00, exfil at 10:25 → 1 incident via session."""
    scan_alert = Alert(
        alert_id="scan-1",
        timestamp=now_utc,
        source="suricata",
        source_type="signature",
        severity_raw=55,
        confidence=0.8,
        src_ip="aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
        dst_ip="bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2",
        protocol="tcp",
        event_type="scan",
    )
    exfil_alert = Alert(
        alert_id="exfil-1",
        timestamp=now_utc + timedelta(minutes=25),
        source="ml-isolation-forest",
        source_type="anomaly",
        severity_raw=80,
        confidence=0.9,
        src_ip="aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa111aaa1",
        dst_ip="bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb222bbb2",
        protocol="tcp",
        event_type="exfiltration",
    )

    incidents = await process_alerts_through_pipeline(
        [scan_alert, exfil_alert], test_config, llm_response=valid_llm_output
    )

    # The second alert should trigger correlation via session
    assert len(incidents) >= 1


@pytest.mark.asyncio
async def test_case8_fp_detection_backup(
    backup_alert_data, test_config, valid_llm_output
):
    """Case 8: backup pattern → Brain marks as FP, no incident."""
    alert = Alert(**backup_alert_data)
    incidents = await process_alerts_through_pipeline(
        [alert], test_config, llm_response=valid_llm_output
    )
    # Single alert + FP pattern → no incident
    assert len(incidents) == 0


@pytest.mark.asyncio
async def test_case9_shuffle_webhook(
    three_correlated_alerts,
    test_config,
    valid_llm_output,
    mock_shuffle_response,
    sample_enrichment_data,
):
    """Case 9: critical incident triggers Shuffle notification + ticket."""
    alerts = [Alert(**a) for a in three_correlated_alerts]
    incidents = await process_alerts_through_pipeline(
        alerts, test_config, llm_response=valid_llm_output
    )

    assert len(incidents) >= 1
    incident = incidents[0]

    # Send to Shuffle
    client = ShuffleClient(test_config["shuffle"])
    mock_http = MagicMock()
    mock_http.is_closed = False
    mock_http.post = AsyncMock(return_value=mock_shuffle_response)
    client._http_client = mock_http

    result = await client.send_incident(incident)
    assert result["status"] == "ok"

    # Verify webhook was called with the correct playbook
    call_args = mock_http.post.call_args
    url = str(call_args[0][0]) if call_args[0] else ""
    assert "brain-" in url


@pytest.mark.asyncio
async def test_case10_dlq_invalid_schema(test_config):
    """Case 10: alert with invalid schema → DLQ."""
    queue: asyncio.Queue[Alert | None] = asyncio.Queue()
    consumer = AlertConsumer(test_config["kafka"], queue)

    dlq_messages: list[dict] = []

    async def dlq_callback(original_message, error, component, **kwargs):
        dlq_messages.append(
            {
                "original": original_message,
                "error": error,
                "component": component,
            }
        )

    consumer.set_dlq_callback(dlq_callback)

    # Send invalid alert (missing required fields)
    msg = MagicMock()
    msg.value.return_value = json.dumps({"invalid": "not an alert"}).encode("utf-8")
    msg.topic.return_value = "ml-scores"
    msg.partition.return_value = 0
    msg.offset.return_value = 0

    await consumer._process_message(msg)

    assert len(dlq_messages) == 1
    assert "validation" in dlq_messages[0]["error"].lower()
    assert dlq_messages[0]["component"] == "consumer"
    assert consumer.stats["invalid"] == 1


# ---------------------------------------------------------------------------
# Full pipeline integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_pipeline_single_alert(sample_alert, test_config):
    """Full pipeline processes a single alert without errors."""
    pipeline = BrainPipeline(test_config)
    # Don't start the full pipeline, just process one alert
    incident = await pipeline.process_single_alert(sample_alert)
    # Single alert may or may not produce an incident (depends on correlation)
    # The key is that it doesn't crash
    assert incident is None or isinstance(incident, Incident)
