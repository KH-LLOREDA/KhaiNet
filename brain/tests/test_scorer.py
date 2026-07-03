"""Tests for the scoring engine."""

from __future__ import annotations

import pytest

from src.enricher import Enricher
from src.models import (
    Alert,
    AlertGroup,
    AssetInfo,
    EnrichmentData,
    GeoIpInfo,
    HistoricalContext,
    ThreatIntelInfo,
    severity_to_label,
)
from src.scorer import Scorer


@pytest.fixture
def scorer(test_config):
    return Scorer(test_config)


@pytest.fixture
def high_enrichment():
    """Enrichment with critical asset + malicious threat intel + high deviation."""
    return EnrichmentData(
        asset_info=AssetInfo(hostname="SRV-DB-01", criticality=5),
        threat_intel=ThreatIntelInfo(
            dst_ip_malicious=True, dst_ip_tags=["c2-server", "botnet"]
        ),
        historical_context=HistoricalContext(
            baseline_bytes_out_p99=50000,
            actual_bytes_out=900000,
            deviation_factor=18.0,
        ),
    )


@pytest.fixture
def low_enrichment():
    """Enrichment with low criticality, no threat intel, no deviation."""
    return EnrichmentData(
        asset_info=AssetInfo(criticality=1),
        threat_intel=ThreatIntelInfo(),
        historical_context=HistoricalContext(),
    )


def test_score_basic_high(scorer, three_correlated_alerts, high_enrichment):
    """High severity scenario produces high score."""
    from src.models import Alert

    alerts = [Alert(**a) for a in three_correlated_alerts]
    group = AlertGroup(alerts=alerts, entity="test")
    score = scorer.calculate(group, high_enrichment)

    assert score >= 70
    assert severity_to_label(score) in ("critical", "high")


def test_score_basic_low(scorer, low_severity_alert_data, low_enrichment):
    """Low severity scenario produces low score."""
    alert = Alert(**low_severity_alert_data)
    group = AlertGroup(alerts=[alert], entity="test")
    score = scorer.calculate(group, low_enrichment)

    assert score < 50


def test_score_components(scorer, three_correlated_alerts, high_enrichment):
    """Score components are calculated correctly."""
    from src.models import Alert

    alerts = [Alert(**a) for a in three_correlated_alerts]
    group = AlertGroup(alerts=alerts, entity="test")
    result = scorer.calculate_with_components(group, high_enrichment)

    assert "components" in result
    comps = result["components"]
    assert comps["model_severity"] > 0
    assert comps["asset_criticality"] == 100  # criticality 5 * 20
    assert comps["threat_intel"] == 100  # malicious match
    assert comps["correlation"] == 75  # 3 alerts * 25


def test_score_bonus_threat_intel_critical(
    scorer, three_correlated_alerts, high_enrichment
):
    """Bonus applied: threat_intel=100 + asset_criticality>=80."""
    from src.models import Alert

    alerts = [Alert(**a) for a in three_correlated_alerts]
    group = AlertGroup(alerts=alerts, entity="test")
    result = scorer.calculate_with_components(group, high_enrichment)

    # With criticality 5 (→100) and threat_intel 100, bonus should apply
    assert result["bonus_applied"]


def test_score_bonus_correlation_severity(scorer, high_enrichment):
    """Bonus applied: correlation=100 + model_severity>=70."""
    from datetime import datetime, timezone

    # 4+ alerts with high severity → correlation=100
    alerts = [
        Alert(
            alert_id=f"a-{i}",
            timestamp=datetime.now(timezone.utc),
            source=f"src-{i}",
            source_type="anomaly",
            severity_raw=75,
            confidence=0.85,
            src_ip="same-ip",
            dst_ip="same-dst",
            protocol="tcp",
            event_type="exfiltration",
        )
        for i in range(4)
    ]
    group = AlertGroup(alerts=alerts, entity="same-ip")
    result = scorer.calculate_with_components(group, high_enrichment)

    assert result["components"]["correlation"] == 100
    assert result["components"]["model_severity"] >= 70
    assert result["bonus_applied"]


def test_score_clamped_to_100(scorer, high_enrichment):
    """Score never exceeds 100."""
    from datetime import datetime, timezone

    alerts = [
        Alert(
            alert_id=f"a-{i}",
            timestamp=datetime.now(timezone.utc),
            source=f"src-{i}",
            source_type="anomaly",
            severity_raw=100,
            confidence=1.0,
            src_ip="same-ip",
            dst_ip="same-dst",
            protocol="tcp",
            event_type="exfiltration",
        )
        for i in range(5)
    ]
    group = AlertGroup(alerts=alerts, entity="same-ip")
    score = scorer.calculate(group, high_enrichment)
    assert score <= 100


def test_score_default_asset_criticality(scorer, three_correlated_alerts):
    """Default asset criticality used when no enrichment info."""
    from src.models import Alert

    alerts = [Alert(**a) for a in three_correlated_alerts]
    group = AlertGroup(alerts=alerts, entity="test")
    empty_enrichment = EnrichmentData()
    score = scorer.calculate(group, empty_enrichment)

    # Should use default criticality (2 → 40)
    comps = scorer.calculate_with_components(group, empty_enrichment)
    assert comps["components"]["asset_criticality"] == 40


def test_severity_labels():
    """Severity label mapping is correct."""
    assert severity_to_label(85) == "critical"
    assert severity_to_label(80) == "critical"
    assert severity_to_label(65) == "high"
    assert severity_to_label(60) == "high"
    assert severity_to_label(45) == "medium"
    assert severity_to_label(40) == "medium"
    assert severity_to_label(25) == "low"
    assert severity_to_label(0) == "low"
