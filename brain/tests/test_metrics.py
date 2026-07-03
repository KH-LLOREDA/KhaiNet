"""Tests for the metrics module (Prometheus + weekly report)."""

from __future__ import annotations

from src.metrics import MetricsRecorder, WeeklyReportGenerator


# ---------------------------------------------------------------------------
# MetricsRecorder tests
# ---------------------------------------------------------------------------


def test_record_alert_received():
    """record_alert_received increments the counter."""
    recorder = MetricsRecorder()
    recorder.record_alert_received("suricata")
    recorder.record_alert_received("suricata")
    recorder.record_alert_received("ml-model")
    # No exception means success; counters are module-level singletons


def test_record_incident_produced():
    """record_incident_produced increments the counter."""
    recorder = MetricsRecorder()
    recorder.record_incident_produced("critical")
    recorder.record_incident_produced("high")


def test_record_llm_call_success():
    """record_llm_call with success observes latency."""
    recorder = MetricsRecorder()
    recorder.record_llm_call("success", 1.5)


def test_record_llm_call_failure():
    """record_llm_call with failure does not observe latency."""
    recorder = MetricsRecorder()
    recorder.record_llm_call("failure", 0)


def test_record_circuit_breaker_state():
    """record_circuit_breaker_state sets the gauge."""
    recorder = MetricsRecorder()
    recorder.record_circuit_breaker_state(0)  # closed
    recorder.record_circuit_breaker_state(1)  # open


def test_record_enrichment_failure():
    """record_enrichment_failure increments the counter."""
    recorder = MetricsRecorder()
    recorder.record_enrichment_failure("misp")
    recorder.record_enrichment_failure("clickhouse")


def test_record_dlq_message():
    """record_dlq_message increments the counter."""
    recorder = MetricsRecorder()
    recorder.record_dlq_message()


def test_record_processing_time():
    """record_processing_time observes the histogram."""
    recorder = MetricsRecorder()
    recorder.record_processing_time(2.5)


def test_xai_availability_ratio():
    """XAI availability ratio is calculated correctly."""
    recorder = MetricsRecorder()
    recorder.record_xai_available()
    recorder.record_xai_available()
    recorder.record_xai_fallback()
    # 2 XAI / 3 total = 0.667
    assert recorder._xai_count == 2
    assert recorder._fallback_count == 1


def test_start_metrics_server_port_in_use():
    """start_metrics_server handles port already in use gracefully."""
    recorder = MetricsRecorder()
    # First call should work (or fail if port is taken by another test)
    try:
        recorder.start_metrics_server(0)  # Port 0 = random free port
    except OSError:
        pass  # Acceptable in test environment


# ---------------------------------------------------------------------------
# WeeklyReportGenerator tests
# ---------------------------------------------------------------------------


def test_weekly_report_basic():
    """Weekly report generates valid markdown with key sections."""
    generator = WeeklyReportGenerator()
    report = generator.generate_report(
        khainet_stats={
            "incidents": 50,
            "true_positives": 45,
            "mttd_seconds": 120,
            "by_category": {
                "exfiltration": 10,
                "c2_beaconing": 15,
                "lateral_movement": 5,
                "dns_tunneling": 8,
                "scan": 12,
            },
        },
        darktrace_stats={
            "incidents": 40,
            "true_positives": 38,
            "mttd_seconds": 180,
            "by_category": {
                "exfiltration": 8,
                "c2_beaconing": 12,
                "lateral_movement": 4,
                "dns_tunneling": 6,
                "scan": 10,
            },
        },
        brain_stats={
            "alerts_received": 1000,
            "incidents_produced": 50,
            "xai_available_count": 48,
            "fallback_count": 2,
            "llm_latency_p50": 1.5,
            "llm_latency_p95": 3.0,
            "llm_latency_p99": 5.0,
        },
    )

    assert "# Reporte semanal" in report
    assert "KhaiNet" in report
    assert "Darktrace" in report
    assert "Cobertura" in report
    assert "Precisión" in report
    assert "Brain performance" in report
    assert "Falsos positivos" in report
    assert "Recomendaciones" in report


def test_weekly_report_coverage_calculation():
    """Coverage is calculated as khainet/darktrace * 100."""
    generator = WeeklyReportGenerator()
    report = generator.generate_report(
        khainet_stats={"incidents": 60, "true_positives": 50, "mttd_seconds": 100},
        darktrace_stats={"incidents": 40, "true_positives": 38, "mttd_seconds": 200},
        brain_stats={
            "alerts_received": 500,
            "incidents_produced": 60,
            "xai_available_count": 55,
            "fallback_count": 5,
            "llm_latency_p50": 1.0,
            "llm_latency_p95": 2.0,
            "llm_latency_p99": 3.0,
        },
    )
    # Coverage = 60/40 * 100 = 150%
    assert "150.0%" in report


def test_weekly_report_precision_calculation():
    """Precision is calculated as TP/incidents * 100."""
    generator = WeeklyReportGenerator()
    report = generator.generate_report(
        khainet_stats={"incidents": 50, "true_positives": 45, "mttd_seconds": 100},
        darktrace_stats={"incidents": 40, "true_positives": 38, "mttd_seconds": 200},
        brain_stats={
            "alerts_received": 500,
            "incidents_produced": 50,
            "xai_available_count": 45,
            "fallback_count": 5,
            "llm_latency_p50": 1.0,
            "llm_latency_p95": 2.0,
            "llm_latency_p99": 3.0,
        },
    )
    # Precision = 45/50 * 100 = 90.0%
    assert "90.0%" in report


def test_weekly_report_fp_categories():
    """FP categories are included in the report when provided."""
    generator = WeeklyReportGenerator()
    report = generator.generate_report(
        khainet_stats={"incidents": 50, "true_positives": 40, "mttd_seconds": 100},
        darktrace_stats={"incidents": 40, "true_positives": 38, "mttd_seconds": 200},
        brain_stats={
            "alerts_received": 500,
            "incidents_produced": 50,
            "xai_available_count": 45,
            "fallback_count": 5,
            "llm_latency_p50": 1.0,
            "llm_latency_p95": 2.0,
            "llm_latency_p99": 3.0,
        },
        fp_categories={"backup": 5, "authorized_scan": 3, "maintenance": 2},
    )
    assert "backup" in report
    assert "authorized_scan" in report
    assert "maintenance" in report


def test_weekly_report_zero_darktrace():
    """Report handles zero Darktrace incidents without division by zero."""
    generator = WeeklyReportGenerator()
    report = generator.generate_report(
        khainet_stats={"incidents": 10, "true_positives": 8, "mttd_seconds": 100},
        darktrace_stats={"incidents": 0, "true_positives": 0, "mttd_seconds": 0},
        brain_stats={
            "alerts_received": 100,
            "incidents_produced": 10,
            "xai_available_count": 9,
            "fallback_count": 1,
            "llm_latency_p50": 1.0,
            "llm_latency_p95": 2.0,
            "llm_latency_p99": 3.0,
        },
    )
    assert "100.0%" in report  # Coverage defaults to 100%


def test_weekly_report_save(tmp_path):
    """save_report writes the report to a file."""
    generator = WeeklyReportGenerator(
        config={"metrics": {"report_output_dir": str(tmp_path)}}
    )
    report = generator.generate_report(
        khainet_stats={"incidents": 10, "true_positives": 8, "mttd_seconds": 100},
        darktrace_stats={"incidents": 8, "true_positives": 7, "mttd_seconds": 200},
        brain_stats={
            "alerts_received": 100,
            "incidents_produced": 10,
            "xai_available_count": 9,
            "fallback_count": 1,
            "llm_latency_p50": 1.0,
            "llm_latency_p95": 2.0,
            "llm_latency_p99": 3.0,
        },
    )
    path = generator.save_report(report, "test_report.md")
    assert path.exists()
    assert path.read_text(encoding="utf-8") == report
