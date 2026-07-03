"""Tests for the XAI (explainability) module."""

from __future__ import annotations

import pytest

from src.models import Alert, AlertGroup, EnrichmentData, Incident, severity_to_label
from src.xai import XAIBuilder


@pytest.fixture
def xai_builder():
    return XAIBuilder()


@pytest.fixture
def alert_group(three_correlated_alerts):
    alerts = [Alert(**a) for a in three_correlated_alerts]
    return AlertGroup(
        alerts=alerts, entity="test-entity", reason="shared_source_proximity"
    )


@pytest.fixture
def enrichment(sample_enrichment_data):
    return EnrichmentData(**sample_enrichment_data)


def test_build_from_llm(xai_builder, alert_group, enrichment, valid_llm_output):
    """Build incident from valid LLM output."""
    incident = xai_builder.build_from_llm(
        group=alert_group,
        enrichment=enrichment,
        severity=82,
        llm_output=valid_llm_output,
        llm_model="brain-kh7-v1",
        llm_latency_ms=3200,
    )

    assert isinstance(incident, Incident)
    assert incident.xai_available
    assert incident.title == valid_llm_output["title"]
    assert incident.explanation == valid_llm_output["explanation"]
    assert incident.llm_model == "brain-kh7-v1"
    assert incident.llm_latency_ms == 3200
    assert len(incident.recommended_actions) == 2
    assert incident.recommended_actions[0].auto_execute  # notify_soc
    assert not incident.recommended_actions[1].auto_execute  # isolate_host


def test_build_fallback(xai_builder, alert_group, enrichment):
    """Build incident without LLM (fallback)."""
    incident = xai_builder.build_fallback(
        group=alert_group,
        enrichment=enrichment,
        severity=82,
    )

    assert isinstance(incident, Incident)
    assert not incident.xai_available
    assert incident.explanation is None
    assert incident.llm_model is None
    assert "needs_xai_reprocess" in incident.tags
    assert "LLM no disponible" in incident.description


def test_fallback_actions_critical(xai_builder, alert_group, enrichment):
    """Fallback actions for critical severity include notify + isolate."""
    incident = xai_builder.build_fallback(
        group=alert_group, enrichment=enrichment, severity=85
    )

    actions = {a.action for a in incident.recommended_actions}
    assert "notify_soc" in actions
    assert "isolate_host" in actions
    # Isolate should not auto-execute
    isolate = next(
        a for a in incident.recommended_actions if a.action == "isolate_host"
    )
    assert not isolate.auto_execute


def test_fallback_actions_low(xai_builder, alert_group, enrichment):
    """Fallback actions for low severity → log only."""
    incident = xai_builder.build_fallback(
        group=alert_group, enrichment=enrichment, severity=25
    )

    actions = {a.action for a in incident.recommended_actions}
    assert "log_only" in actions


def test_timeline_built(xai_builder, alert_group, enrichment, valid_llm_output):
    """Timeline is built from alerts in chronological order."""
    incident = xai_builder.build_from_llm(
        group=alert_group,
        enrichment=enrichment,
        severity=82,
        llm_output=valid_llm_output,
        llm_model="test",
        llm_latency_ms=100,
    )

    assert len(incident.timeline) >= len(alert_group.alerts) + 1  # alerts + Brain entry
    # Check that alert entries are in chronological order (excluding the Brain entry)
    alert_timestamps = [t.timestamp for t in incident.timeline[:-1]]
    assert alert_timestamps == sorted(alert_timestamps)


def test_metrics_built(xai_builder, alert_group, enrichment, valid_llm_output):
    """Incident metrics are calculated correctly."""
    incident = xai_builder.build_from_llm(
        group=alert_group,
        enrichment=enrichment,
        severity=82,
        llm_output=valid_llm_output,
        llm_model="test",
        llm_latency_ms=100,
    )

    assert incident.metrics.alert_count == 3
    assert incident.metrics.unique_sources == 3
    assert incident.metrics.unique_destinations == 1
    assert incident.metrics.time_span_seconds > 0


def test_destructive_actions_not_auto(xai_builder, alert_group, enrichment):
    """Destructive actions from LLM are forced to auto_execute=False."""
    llm_output = {
        "title": "Test",
        "description": "Test",
        "explanation": "Test",
        "correlation_reason": "Test",
        "false_positive_assessment": "Test",
        "severity_adjustment": 0,
        "confidence": 0.8,
        "recommended_actions": [
            {
                "action": "isolate_host",
                "target": "SRV-DB-01",
                "priority": "high",
                "auto_execute": True,  # LLM said True
                "justification": "test",
            },
            {
                "action": "block_ip",
                "target": "1.2.3.4",
                "priority": "high",
                "auto_execute": True,  # LLM said True
                "justification": "test",
            },
        ],
    }

    incident = xai_builder.build_from_llm(
        group=alert_group,
        enrichment=enrichment,
        severity=82,
        llm_output=llm_output,
        llm_model="test",
        llm_latency_ms=100,
    )

    for action in incident.recommended_actions:
        if action.action in ("isolate_host", "block_ip"):
            assert not action.auto_execute


def test_severity_adjustment_applied(
    xai_builder, alert_group, enrichment, valid_llm_output
):
    """LLM severity adjustment is applied and clamped."""
    valid_llm_output["severity_adjustment"] = 10
    incident = xai_builder.build_from_llm(
        group=alert_group,
        enrichment=enrichment,
        severity=75,
        llm_output=valid_llm_output,
        llm_model="test",
        llm_latency_ms=100,
    )
    assert incident.severity == 85  # 75 + 10


def test_severity_adjustment_clamped(
    xai_builder, alert_group, enrichment, valid_llm_output
):
    """Severity adjustment is clamped to 0-100."""
    valid_llm_output["severity_adjustment"] = 50
    incident = xai_builder.build_from_llm(
        group=alert_group,
        enrichment=enrichment,
        severity=90,
        llm_output=valid_llm_output,
        llm_model="test",
        llm_latency_ms=100,
    )
    assert incident.severity == 100  # clamped
