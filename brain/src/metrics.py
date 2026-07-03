"""Prometheus metrics and weekly report generator for KhaiNet Brain.

Exports internal metrics via prometheus-client and generates a weekly
markdown report comparing KhaiNet vs Darktrace.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import structlog
from prometheus_client import Counter, Gauge, Histogram, start_http_server

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Prometheus metrics (module-level singletons)
# ---------------------------------------------------------------------------

ALERTS_RECEIVED = Counter(
    "brain_alerts_received_total",
    "Alertas recibidas por source",
    ["source"],
)

INCIDENTS_PRODUCED = Counter(
    "brain_incidents_produced_total",
    "Incidentes producidos por severity_label",
    ["severity_label"],
)

LLM_CALLS = Counter(
    "brain_llm_calls_total",
    "Llamadas al LLM",
    ["result"],  # success, failure, timeout
)

LLM_LATENCY = Histogram(
    "brain_llm_latency_seconds",
    "Latencia del LLM",
    buckets=(0.5, 1, 2, 3, 5, 10, 20, 30),
)

CIRCUIT_BREAKER_STATE = Gauge(
    "brain_circuit_breaker_state",
    "Estado del circuit breaker (0=closed, 1=open, 2=half)",
)

ENRICHMENT_FAILURES = Counter(
    "brain_enrichment_failures_total",
    "Fallos de enriquecimiento por fuente",
    ["source"],
)

DLQ_MESSAGES = Counter(
    "brain_dlq_messages_total",
    "Mensajes enviados a DLQ",
)

PROCESSING_TIME = Histogram(
    "brain_processing_time_seconds",
    "Tiempo total de procesamiento por incidente",
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60),
)

XAI_AVAILABILITY = Gauge(
    "brain_xai_availability_ratio",
    "Ratio de incidentes con XAI vs fallback",
)


# ---------------------------------------------------------------------------
# Metrics recorder
# ---------------------------------------------------------------------------


class MetricsRecorder:
    """Records metrics during pipeline execution."""

    def __init__(self) -> None:
        self._xai_count = 0
        self._fallback_count = 0

    def record_alert_received(self, source: str) -> None:
        ALERTS_RECEIVED.labels(source=source).inc()

    def record_incident_produced(self, severity_label: str) -> None:
        INCIDENTS_PRODUCED.labels(severity_label=severity_label).inc()

    def record_llm_call(self, result: str, latency_seconds: float) -> None:
        LLM_CALLS.labels(result=result).inc()
        if result == "success":
            LLM_LATENCY.observe(latency_seconds)

    def record_circuit_breaker_state(self, state: int) -> None:
        CIRCUIT_BREAKER_STATE.set(state)

    def record_enrichment_failure(self, source: str) -> None:
        ENRICHMENT_FAILURES.labels(source=source).inc()

    def record_dlq_message(self) -> None:
        DLQ_MESSAGES.inc()

    def record_processing_time(self, seconds: float) -> None:
        PROCESSING_TIME.observe(seconds)

    def record_xai_available(self) -> None:
        self._xai_count += 1
        self._update_xai_ratio()

    def record_xai_fallback(self) -> None:
        self._fallback_count += 1
        self._update_xai_ratio()

    def _update_xai_ratio(self) -> None:
        total = self._xai_count + self._fallback_count
        if total > 0:
            XAI_AVAILABILITY.set(self._xai_count / total)

    def start_metrics_server(self, port: int = 9090) -> None:
        """Start the Prometheus metrics HTTP server."""
        start_http_server(port)
        log.info("metrics_server_started", port=port)


# ---------------------------------------------------------------------------
# Weekly report generator
# ---------------------------------------------------------------------------


class WeeklyReportGenerator:
    """Generates a weekly markdown report comparing KhaiNet vs Darktrace."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        metrics_config = (config or {}).get("metrics", {})
        self.output_dir = Path(metrics_config.get("report_output_dir", "./reports"))
        self.window_days = metrics_config.get("comparison_window_days", 7)

    def generate_report(
        self,
        khainet_stats: dict[str, Any],
        darktrace_stats: dict[str, Any],
        brain_stats: dict[str, Any],
        fp_categories: dict[str, int] | None = None,
    ) -> str:
        """Generate a weekly comparison report in markdown.

        Args:
            khainet_stats: Dict with keys: incidents, true_positives, mttd_seconds
            darktrace_stats: Dict with keys: incidents, true_positives, mttd_seconds
            brain_stats: Dict with keys: alerts_received, incidents_produced,
                          xai_available_count, fallback_count, llm_latency_p50,
                          llm_latency_p95, llm_latency_p99
            fp_categories: Dict mapping FP category names to counts.

        Returns:
            Markdown report string.
        """
        now = datetime.now(timezone.utc)
        week_start = now - timedelta(days=self.window_days)

        khainet_incidents = khainet_stats.get("incidents", 0)
        darktrace_incidents = darktrace_stats.get("incidents", 0)
        khainet_tp = khainet_stats.get("true_positives", 0)

        # Calculate KPIs
        coverage = (
            (khainet_incidents / darktrace_incidents * 100)
            if darktrace_incidents > 0
            else 100.0
        )
        precision = (
            (khainet_tp / khainet_incidents * 100) if khainet_incidents > 0 else 0.0
        )
        advantage = khainet_incidents - darktrace_incidents

        khainet_mttd = khainet_stats.get("mttd_seconds", 0) / 60  # to minutes
        darktrace_mttd = darktrace_stats.get("mttd_seconds", 0) / 60
        mttd_diff_pct = (
            ((khainet_mttd - darktrace_mttd) / darktrace_mttd * 100)
            if darktrace_mttd > 0
            else 0.0
        )

        fp_count = khainet_incidents - khainet_tp
        fp_rate = (fp_count / khainet_incidents * 100) if khainet_incidents > 0 else 0.0

        alerts_received = brain_stats.get("alerts_received", 0)
        incidents_produced = brain_stats.get("incidents_produced", 0)
        reduction = (
            ((alerts_received - incidents_produced) / alerts_received * 100)
            if alerts_received > 0
            else 0.0
        )

        xai_count = brain_stats.get("xai_available_count", 0)
        fallback_count = brain_stats.get("fallback_count", 0)
        total_incidents = xai_count + fallback_count
        xai_availability = (
            (xai_count / total_incidents * 100) if total_incidents > 0 else 0.0
        )

        llm_p50 = brain_stats.get("llm_latency_p50", 0)
        llm_p95 = brain_stats.get("llm_latency_p95", 0)
        llm_p99 = brain_stats.get("llm_latency_p99", 0)

        report = f"""# Reporte semanal KhaiNet vs Darktrace — Semana del {week_start.strftime("%Y-%m-%d")} al {now.strftime("%Y-%m-%d")}

## Resumen ejecutivo
- KhaiNet detectó {khainet_incidents} incidentes vs {darktrace_incidents} de Darktrace
- Cobertura: {coverage:.1f}% ({khainet_incidents}/{darktrace_incidents})
- Precisión: {precision:.1f}% ({khainet_tp}/{khainet_incidents} TP)
- Ventaja: {advantage} incidentes detectados solo por KhaiNet
- MTTD KhaiNet: {khainet_mttd:.1f} min vs Darktrace {darktrace_mttd:.1f} min ({mttd_diff_pct:+.1f}%)

## Detalle por categoría
| Categoría | KhaiNet | Darktrace | Cobertura |
|-----------|---------|-----------|-----------|
| Exfiltración | {khainet_stats.get("by_category", {}).get("exfiltration", 0)} | {darktrace_stats.get("by_category", {}).get("exfiltration", 0)} | — |
| C2 Beaconing | {khainet_stats.get("by_category", {}).get("c2_beaconing", 0)} | {darktrace_stats.get("by_category", {}).get("c2_beaconing", 0)} | — |
| Lateral Movement | {khainet_stats.get("by_category", {}).get("lateral_movement", 0)} | {darktrace_stats.get("by_category", {}).get("lateral_movement", 0)} | — |
| DNS Tunneling | {khainet_stats.get("by_category", {}).get("dns_tunneling", 0)} | {darktrace_stats.get("by_category", {}).get("dns_tunneling", 0)} | — |
| Scan | {khainet_stats.get("by_category", {}).get("scan", 0)} | {darktrace_stats.get("by_category", {}).get("scan", 0)} | — |

## Brain performance
- Alertas recibidas: {alerts_received:,}
- Incidentes producidos: {incidents_produced} (reducción {reduction:.1f}%)
- XAI disponible: {xai_availability:.1f}% ({fallback_count} incidentes en fallback)
- LLM latency p50: {llm_p50:.1f}s, p95: {llm_p95:.1f}s, p99: {llm_p99:.1f}s

## Falsos positivos
- FP rate: {fp_rate:.1f}% ({fp_count}/{khainet_incidents})
"""

        if fp_categories:
            report += "- Categorías más frecuentes de FP:\n"
            for cat, count in sorted(
                fp_categories.items(), key=lambda x: x[1], reverse=True
            ):
                report += f"  - {cat}: {count}\n"

        report += """
## Recomendaciones
- Ajustar pesos del scorer basado en calibraciones de analistas
- Revisar patrones de FP más frecuentes para añadir reglas de filtrado
- Monitorizar latencia del LLM y ajustar timeout si p95 > 5s
- Verificar que XAI availability se mantenga > 95%
"""
        return report

    def save_report(self, report: str, filename: str | None = None) -> Path:
        """Save the report to a file and return the path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if filename is None:
            now = datetime.now(timezone.utc)
            filename = f"weekly_report_{now.strftime('%Y%m%d')}.md"
        path = self.output_dir / filename
        path.write_text(report, encoding="utf-8")
        log.info("weekly_report_saved", path=str(path))
        return path
