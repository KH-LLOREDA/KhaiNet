"""Explainability (XAI) module for KhaiNet Brain.

Builds the narrative and explanation components of an incident from:
1. LLM output (when available)
2. Mathematical fallback (when LLM is unavailable)

Constructs the 6 XAI components:
- Title, Description, Explanation, Correlation reason, FP assessment, Actions
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.models import (
    Alert,
    AlertGroup,
    EnrichmentData,
    Incident,
    IncidentEntities,
    IncidentMetrics,
    IncidentStatus,
    RecommendedAction,
    TimelineEntry,
    severity_to_label,
)

log = structlog.get_logger()


class XAIBuilder:
    """Builds incident explanations from LLM output or mathematical fallback."""

    def __init__(self) -> None:
        self._fallback_counter = 0

    # ------------------------------------------------------------------
    # Build from LLM output
    # ------------------------------------------------------------------

    def build_from_llm(
        self,
        group: AlertGroup,
        enrichment: EnrichmentData,
        severity: int,
        llm_output: dict[str, Any],
        llm_model: str,
        llm_latency_ms: int,
    ) -> Incident:
        """Build a complete incident from LLM output."""
        label = severity_to_label(severity)

        # Apply severity adjustment from LLM (clamped to 0-100)
        adjustment = llm_output.get("severity_adjustment", 0)
        adjusted_severity = max(0, min(100, severity + adjustment))
        if adjustment != 0:
            label = severity_to_label(adjusted_severity)

        # Build recommended actions
        actions = self._build_actions(llm_output.get("recommended_actions", []))

        # Build timeline
        timeline = self._build_timeline(group)

        # Build entities
        entities = self._build_entities(group)

        # Build metrics
        metrics = self._build_metrics(group)

        # Build description from LLM or fallback
        description = llm_output.get(
            "description", self._fallback_description(group, severity)
        )

        incident = Incident(
            severity=adjusted_severity,
            severity_label=label,
            confidence=llm_output.get("confidence", 0.5),
            title=llm_output.get("title", self._fallback_title(group, severity)),
            description=description,
            explanation=llm_output.get("explanation"),
            correlation_reason=llm_output.get(
                "correlation_reason", self._fallback_correlation_reason(group)
            ),
            false_positive_assessment=llm_output.get(
                "false_positive_assessment",
                "Evaluación no disponible (procesado sin LLM).",
            ),
            recommended_actions=actions,
            alerts=group.alerts,
            entities=entities,
            enrichment=enrichment,
            timeline=timeline,
            metrics=metrics,
            xai_available=True,
            llm_model=llm_model,
            llm_latency_ms=llm_latency_ms,
            status=IncidentStatus.NEW,
        )

        log.info(
            "incident_built_with_xai",
            incident_id=incident.incident_id,
            severity=adjusted_severity,
            alert_count=len(group.alerts),
            llm_latency_ms=llm_latency_ms,
        )
        return incident

    # ------------------------------------------------------------------
    # Build fallback (no LLM)
    # ------------------------------------------------------------------

    def build_fallback(
        self,
        group: AlertGroup,
        enrichment: EnrichmentData,
        severity: int,
        confidence: float = 0.5,
    ) -> Incident:
        """Build an incident without LLM explanation (mathematical fallback).

        The incident is tagged ``needs_xai_reprocess`` for later reprocessing.
        """
        label = severity_to_label(severity)
        self._fallback_counter += 1

        actions = self._build_fallback_actions(severity, group, enrichment)
        timeline = self._build_timeline(group)
        entities = self._build_entities(group)
        metrics = self._build_metrics(group)

        incident = Incident(
            severity=severity,
            severity_label=label,
            confidence=confidence,
            title=self._fallback_title(group, severity),
            description=self._fallback_description(group, severity),
            explanation=None,
            correlation_reason=self._fallback_correlation_reason(group),
            false_positive_assessment=self._fallback_fp_assessment(group, enrichment),
            recommended_actions=actions,
            alerts=group.alerts,
            entities=entities,
            enrichment=enrichment,
            timeline=timeline,
            metrics=metrics,
            xai_available=False,
            llm_model=None,
            llm_latency_ms=None,
            status=IncidentStatus.NEW,
            tags=["needs_xai_reprocess"],
        )

        log.info(
            "incident_built_fallback",
            incident_id=incident.incident_id,
            severity=severity,
            alert_count=len(group.alerts),
        )
        return incident

    # ------------------------------------------------------------------
    # Helper builders
    # ------------------------------------------------------------------

    def _build_actions(
        self, raw_actions: list[dict[str, Any]]
    ) -> list[RecommendedAction]:
        """Convert LLM action dicts to RecommendedAction models."""
        actions: list[RecommendedAction] = []
        for raw in raw_actions:
            if not isinstance(raw, dict):
                continue
            action = raw.get("action", "")
            target = raw.get("target", "")
            # Destructive actions must not auto-execute
            auto = raw.get("auto_execute", False)
            if action in ("isolate_host", "block_ip", "block_domain", "quarantine"):
                auto = False
            try:
                actions.append(
                    RecommendedAction(
                        action=action,
                        target=target,
                        priority=raw.get("priority", "medium"),
                        auto_execute=auto,
                        justification=raw.get("justification", ""),
                    )
                )
            except (ValueError, TypeError) as e:
                log.warning("invalid_action_skipped", action=action, error=str(e))
        return actions

    def _build_fallback_actions(
        self, severity: int, group: AlertGroup, enrichment: EnrichmentData
    ) -> list[RecommendedAction]:
        """Generate default actions based on severity (no LLM)."""
        actions: list[RecommendedAction] = []

        if severity >= 80:
            actions.append(
                RecommendedAction(
                    action="notify_soc",
                    target="soc-team",
                    priority="immediate",
                    auto_execute=True,
                    justification="Severidad crítica requiere notificación inmediata",
                )
            )
            actions.append(
                RecommendedAction(
                    action="create_ticket",
                    target="thehive",
                    priority="immediate",
                    auto_execute=True,
                    justification="Crear caso para tracking",
                )
            )
            # Destructive actions require human approval
            src_hosts = group.get_src_hosts()
            target_host = src_hosts[0] if src_hosts else group.entity
            actions.append(
                RecommendedAction(
                    action="isolate_host",
                    target=target_host,
                    priority="high",
                    auto_execute=False,
                    justification="Aislamiento requiere aprobación humana",
                )
            )
        elif severity >= 60:
            actions.append(
                RecommendedAction(
                    action="notify_soc",
                    target="soc-team",
                    priority="high",
                    auto_execute=True,
                    justification="Severidad alta requiere notificación",
                )
            )
            actions.append(
                RecommendedAction(
                    action="create_ticket",
                    target="thehive",
                    priority="high",
                    auto_execute=True,
                    justification="Crear caso para tracking",
                )
            )
        elif severity >= 40:
            actions.append(
                RecommendedAction(
                    action="create_ticket",
                    target="thehive",
                    priority="medium",
                    auto_execute=True,
                    justification="Crear caso para monitorización",
                )
            )
        else:
            actions.append(
                RecommendedAction(
                    action="log_only",
                    target="opensearch",
                    priority="low",
                    auto_execute=True,
                    justification="Severidad baja, solo logging",
                )
            )

        return actions

    def _build_timeline(self, group: AlertGroup) -> list[TimelineEntry]:
        """Build a chronological timeline from the alert group."""
        entries: list[TimelineEntry] = []
        sorted_alerts = sorted(group.alerts, key=lambda a: a.ts_epoch)
        for alert in sorted_alerts:
            event_desc = self._describe_alert(alert)
            entries.append(
                TimelineEntry(
                    timestamp=alert.timestamp.isoformat().replace("+00:00", "Z"),
                    event=event_desc,
                )
            )
        # Add Brain processing entry
        entries.append(
            TimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                event="Brain: incidente correlacionado y publicado",
            )
        )
        return entries

    def _describe_alert(self, alert: Alert) -> str:
        """Create a human-readable description of a single alert."""
        parts: list[str] = []
        if alert.source:
            parts.append(alert.source)
        if alert.event_type:
            et = (
                alert.event_type
                if isinstance(alert.event_type, str)
                else alert.event_type.value
            )
            parts.append(f"({et})")
        if alert.ml_score is not None:
            parts.append(f"score {alert.ml_score}")
        if alert.severity_raw is not None:
            parts.append(f"severidad {alert.severity_raw}")
        if alert.rule_message:
            parts.append(f"— {alert.rule_message}")
        return " ".join(parts) if parts else f"Alerta {alert.alert_id[:8]}"

    def _build_entities(self, group: AlertGroup) -> IncidentEntities:
        """Extract entities from the alert group."""
        return IncidentEntities(
            src_hosts=group.get_src_hosts(),
            dst_hosts=[],  # Would be populated from enrichment
            src_ips=group.get_src_ips(),
            dst_ips=group.get_dst_ips(),
        )

    def _build_metrics(self, group: AlertGroup) -> IncidentMetrics:
        """Calculate incident metrics from the alert group."""
        return IncidentMetrics(
            alert_count=group.alert_count,
            time_span_seconds=group.time_span_seconds(),
            unique_sources=group.unique_sources(),
            unique_destinations=group.unique_destinations(),
        )

    # ------------------------------------------------------------------
    # Fallback text generators
    # ------------------------------------------------------------------

    def _fallback_title(self, group: AlertGroup, severity: int) -> str:
        """Generate a title without LLM."""
        event_types = {a.event_type for a in group.alerts}
        et_str = ", ".join(event_types) if event_types else "anomalía"
        return f"Incidente correlacionado: {et_str} ({group.alert_count} alertas, severidad {severity})"

    def _fallback_description(self, group: AlertGroup, severity: int) -> str:
        """Generate a description without LLM."""
        desc = (
            f"Incidente correlacionado por scoring automático (LLM no disponible). "
            f"{len(group.alerts)} alertas, severidad {severity}. "
        )
        event_types = {a.event_type for a in group.alerts}
        if event_types:
            desc += f"Tipos de evento: {', '.join(event_types)}. "
        desc += f"Entidad: {group.entity}. "
        if group.pattern_name:
            desc += f"Patrón detectado: {group.pattern_name}."
        return desc

    def _fallback_correlation_reason(self, group: AlertGroup) -> str:
        """Generate a correlation reason without LLM."""
        reason = f"Las {len(group.alerts)} alertas comparten la misma entidad ({group.entity})"
        if group.reason.startswith("attack_pattern"):
            reason += f" y siguen el patrón de ataque {group.pattern_name}"
        else:
            reason += " y ocurren en proximidad temporal"
        reason += "."
        return reason

    def _fallback_fp_assessment(
        self, group: AlertGroup, enrichment: EnrichmentData
    ) -> str:
        """Generate a FP assessment without LLM."""
        assessment = "Evaluación automática (sin LLM): "
        if enrichment.threat_intel.dst_ip_malicious:
            assessment += (
                "IP destino marcada como maliciosa en threat intel. FP descartado."
            )
        elif (
            enrichment.historical_context.deviation_factor
            and enrichment.historical_context.deviation_factor > 5
        ):
            assessment += (
                "Desviación significativa del baseline histórico. FP improbable."
            )
        else:
            assessment += "Datos insuficientes para evaluación automática. Requiere revisión manual."
        return assessment

    @property
    def fallback_count(self) -> int:
        return self._fallback_counter
