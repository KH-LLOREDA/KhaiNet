"""Composite severity scoring engine for KhaiNet Brain.

Calculates a 0-100 severity score from 5 weighted components:
- model_severity (40%) — weighted average of alert severity_raw
- asset_criticality (25%) — criticality level 1-5 mapped to 0-100
- threat_intel (15%) — MISP match: 100 if malicious, 50 if suspicious, 0 if none
- historical (10%) — deviation from baseline
- correlation (10%) — number and coherence of correlated alerts

Applies non-linear bonus for extreme cases.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.models import AlertGroup, EnrichmentData, severity_to_label

log = structlog.get_logger()


class Scorer:
    """Composite severity scorer with configurable weights and bonuses."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        scoring_config = (config or {}).get("scoring", {})
        weights = scoring_config.get("weights", {})
        self.weights = {
            "model_severity": weights.get("model_severity", 0.40),
            "asset_criticality": weights.get("asset_criticality", 0.25),
            "threat_intel": weights.get("threat_intel", 0.15),
            "historical": weights.get("historical", 0.10),
            "correlation": weights.get("correlation", 0.10),
        }
        self.default_asset_criticality = scoring_config.get(
            "default_asset_criticality", 2
        )
        bonus_cfg = scoring_config.get("bonus", {})
        self.bonus_ti_threshold = bonus_cfg.get("threat_intel_critical_threshold", 100)
        self.bonus_asset_threshold = bonus_cfg.get("asset_criticality_threshold", 80)
        self.bonus_corr_threshold = bonus_cfg.get("correlation_strong_threshold", 100)
        self.bonus_model_threshold = bonus_cfg.get("model_severity_high_threshold", 70)

    # ------------------------------------------------------------------
    # Individual component calculations
    # ------------------------------------------------------------------

    def calc_model_severity(self, group: AlertGroup) -> float:
        """Weighted average of severity_raw by confidence."""
        if not group.alerts:
            return 0.0
        total_weight = sum(a.confidence for a in group.alerts)
        if total_weight == 0:
            # Fallback to simple average
            return sum(a.severity_raw for a in group.alerts) / len(group.alerts)
        weighted = sum(a.severity_raw * a.confidence for a in group.alerts)
        return weighted / total_weight

    def calc_asset_criticality(self, enrichment: EnrichmentData) -> float:
        """Map criticality 1-5 to 0-100. Default 40 if no info."""
        criticality = enrichment.asset_info.criticality
        if criticality is None or criticality == 0:
            criticality = self.default_asset_criticality
        return float(criticality * 20)

    def calc_threat_intel(self, enrichment: EnrichmentData) -> float:
        """100 if malicious match, 50 if suspicious tags, 0 if no match."""
        ti = enrichment.threat_intel
        if ti.dst_ip_malicious or ti.src_ip_malicious:
            return 100.0
        suspicious_tags = {"c2-server", "botnet", "malware", "phishing", "suspicious"}
        all_tags = set(ti.dst_ip_tags) | set(ti.src_ip_tags)
        if all_tags & suspicious_tags:
            return 50.0
        return 0.0

    def calc_historical_deviation(self, enrichment: EnrichmentData) -> float:
        """min(100, deviation_factor * 10)."""
        hist = enrichment.historical_context
        if hist.deviation_factor is None:
            return 0.0
        return min(100.0, hist.deviation_factor * 10)

    def calc_correlation_strength(self, group: AlertGroup) -> float:
        """min(100, alert_count * 25). 1=25, 2=50, 3=75, 4+=100."""
        return min(100.0, float(group.alert_count * 25))

    # ------------------------------------------------------------------
    # Composite score
    # ------------------------------------------------------------------

    def calculate(self, group: AlertGroup, enrichment: EnrichmentData) -> int:
        """Calculate the composite severity score (0-100).

        Applies non-linear bonus for extreme cases:
        - threat_intel=100 + asset_criticality>=80 → +20%
        - correlation=100 + model_severity>=70 → +10%
        """
        model_sev = self.calc_model_severity(group)
        asset_crit = self.calc_asset_criticality(enrichment)
        threat_intel = self.calc_threat_intel(enrichment)
        historical = self.calc_historical_deviation(enrichment)
        correlation = self.calc_correlation_strength(group)

        severity = (
            model_sev * self.weights["model_severity"]
            + asset_crit * self.weights["asset_criticality"]
            + threat_intel * self.weights["threat_intel"]
            + historical * self.weights["historical"]
            + correlation * self.weights["correlation"]
        )

        # Non-linear bonus for extreme cases
        if (
            threat_intel >= self.bonus_ti_threshold
            and asset_crit >= self.bonus_asset_threshold
        ):
            severity = min(100, severity * 1.2)
        if (
            correlation >= self.bonus_corr_threshold
            and model_sev >= self.bonus_model_threshold
        ):
            severity = min(100, severity * 1.1)

        result = round(severity)
        result = max(0, min(100, result))

        log.debug(
            "score_calculated",
            severity=result,
            model_severity=model_sev,
            asset_criticality=asset_crit,
            threat_intel=threat_intel,
            historical=historical,
            correlation=correlation,
            alert_count=group.alert_count,
        )
        return result

    def calculate_with_components(
        self, group: AlertGroup, enrichment: EnrichmentData
    ) -> dict[str, Any]:
        """Calculate score and return all components for transparency."""
        model_sev = self.calc_model_severity(group)
        asset_crit = self.calc_asset_criticality(enrichment)
        threat_intel = self.calc_threat_intel(enrichment)
        historical = self.calc_historical_deviation(enrichment)
        correlation = self.calc_correlation_strength(group)

        severity = (
            model_sev * self.weights["model_severity"]
            + asset_crit * self.weights["asset_criticality"]
            + threat_intel * self.weights["threat_intel"]
            + historical * self.weights["historical"]
            + correlation * self.weights["correlation"]
        )

        bonus_applied = False
        if (
            threat_intel >= self.bonus_ti_threshold
            and asset_crit >= self.bonus_asset_threshold
        ):
            severity = min(100, severity * 1.2)
            bonus_applied = True
        if (
            correlation >= self.bonus_corr_threshold
            and model_sev >= self.bonus_model_threshold
        ):
            severity = min(100, severity * 1.1)
            bonus_applied = True

        result = max(0, min(100, round(severity)))
        return {
            "severity": result,
            "severity_label": severity_to_label(result).value,
            "components": {
                "model_severity": model_sev,
                "asset_criticality": asset_crit,
                "threat_intel": threat_intel,
                "historical": historical,
                "correlation": correlation,
            },
            "weights": self.weights,
            "bonus_applied": bonus_applied,
        }
