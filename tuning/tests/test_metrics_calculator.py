"""Tests for the metrics calculator."""

from __future__ import annotations

import pytest

from src.metrics_calculator import (
    calculate_confusion_matrix,
    calculate_metrics,
    gap_analysis,
    generate_confusion_matrix_report,
)
from src.models import ConfusionMatrix, TuningMetrics


class TestConfusionMatrix:
    def test_basic_confusion_matrix(self):
        predictions = [True, True, False, False, True, False]
        labels = [True, False, True, False, True, False]
        cm = calculate_confusion_matrix(predictions, labels)
        # TP: pred=T, label=T → indices 0, 4 → 2
        # FP: pred=T, label=F → index 1 → 1
        # FN: pred=F, label=T → index 2 → 1
        # TN: pred=F, label=F → indices 3, 5 → 2
        assert cm.true_positive == 2
        assert cm.false_positive == 1
        assert cm.false_negative == 1
        assert cm.true_negative == 2
        assert cm.total_events == 6

    def test_all_correct(self):
        predictions = [True, False, True, False]
        labels = [True, False, True, False]
        cm = calculate_confusion_matrix(predictions, labels)
        assert cm.true_positive == 2
        assert cm.false_positive == 0
        assert cm.false_negative == 0
        assert cm.true_negative == 2

    def test_all_wrong(self):
        predictions = [True, True, False, False]
        labels = [False, False, True, True]
        cm = calculate_confusion_matrix(predictions, labels)
        assert cm.true_positive == 0
        assert cm.false_positive == 2
        assert cm.false_negative == 2
        assert cm.true_negative == 0

    def test_empty(self):
        cm = calculate_confusion_matrix([], [])
        assert cm.total_events == 0


class TestCalculateMetrics:
    def test_coverage_calculated_correctly(self):
        """Coverage = TP / (TP + FN) * 100."""
        # DT detects 10 incidents (TP+FN=10), KhaiNet detects 9 of them (TP=9)
        predictions = [True] * 9 + [False] + [False] * 90
        labels = [True] * 10 + [False] * 90
        metrics = calculate_metrics(predictions, labels)
        assert metrics.coverage == 90.0  # 9/10 * 100

    def test_precision_calculated_correctly(self):
        """Precision = TP / (TP + FP) * 100."""
        # KhaiNet alerts: 9 TP + 1 FP = 10 total
        predictions = [True] * 10 + [False] * 90
        labels = [True] * 9 + [False] + [False] * 90
        metrics = calculate_metrics(predictions, labels)
        assert metrics.precision == 90.0  # 9/10 * 100

    def test_advantage_calculated(self):
        """Advantage = incidents KhaiNet detects that DT doesn't = FP."""
        predictions = [True, True, True, False]
        labels = [True, False, False, False]
        metrics = calculate_metrics(predictions, labels)
        # FP = 2 (KhaiNet detects 2 that DT doesn't)
        assert metrics.advantage == 2

    def test_mttd_calculated(self):
        predictions = [True, True, False]
        labels = [True, True, False]
        khainet_latencies = [10.0, 20.0]
        darktrace_latencies = [15.0, 25.0]
        metrics = calculate_metrics(
            predictions, labels, khainet_latencies, darktrace_latencies
        )
        assert metrics.mttd_khainet_seconds == 15.0  # (10+20)/2
        assert metrics.mttd_darktrace_seconds == 20.0  # (15+25)/2

    def test_mttd_diff_pct(self):
        predictions = [True, True]
        labels = [True, True]
        khainet_latencies = [10.0, 20.0]  # mean=15
        darktrace_latencies = [15.0, 25.0]  # mean=20
        metrics = calculate_metrics(
            predictions, labels, khainet_latencies, darktrace_latencies
        )
        # (15 - 20) / 20 * 100 = -25%
        assert metrics.mttd_diff_pct == -25.0

    def test_no_latencies(self):
        predictions = [True, False]
        labels = [True, False]
        metrics = calculate_metrics(predictions, labels)
        assert metrics.mttd_khainet_seconds == 0.0
        assert metrics.mttd_darktrace_seconds == 0.0
        assert metrics.mttd_diff_pct == 0.0

    def test_confusion_matrix_in_metrics(self):
        predictions = [True, False, True, False]
        labels = [True, True, True, False]
        metrics = calculate_metrics(predictions, labels)
        assert isinstance(metrics.confusion_matrix, ConfusionMatrix)
        assert metrics.confusion_matrix.true_positive == 2
        assert metrics.confusion_matrix.false_negative == 1


class TestGapAnalysis:
    def test_all_targets_met(self):
        metrics = TuningMetrics(
            coverage=95.0,
            precision=90.0,
            advantage=5,
            mttd_diff_pct=10.0,
            confusion_matrix=ConfusionMatrix(),
        )
        targets = {
            "coverage": 90.0,
            "precision": 85.0,
            "advantage": 0,
            "latency_diff_pct": 30.0,
        }
        gaps = gap_analysis(metrics, targets)
        assert gaps["all_targets_met"] is True
        assert gaps["coverage"]["met"] is True
        assert gaps["precision"]["met"] is True
        assert gaps["advantage"]["met"] is True
        assert gaps["latency"]["met"] is True

    def test_coverage_not_met(self):
        metrics = TuningMetrics(
            coverage=80.0,
            precision=90.0,
            advantage=5,
            mttd_diff_pct=10.0,
        )
        targets = {
            "coverage": 90.0,
            "precision": 85.0,
            "advantage": 0,
            "latency_diff_pct": 30.0,
        }
        gaps = gap_analysis(metrics, targets)
        assert gaps["all_targets_met"] is False
        assert gaps["coverage"]["met"] is False
        assert gaps["coverage"]["gap"] == 10.0

    def test_latency_not_met(self):
        metrics = TuningMetrics(
            coverage=95.0,
            precision=90.0,
            advantage=5,
            mttd_diff_pct=50.0,  # > 30% target
        )
        targets = {
            "coverage": 90.0,
            "precision": 85.0,
            "advantage": 0,
            "latency_diff_pct": 30.0,
        }
        gaps = gap_analysis(metrics, targets)
        assert gaps["latency"]["met"] is False

    def test_default_targets(self):
        metrics = TuningMetrics(
            coverage=95.0,
            precision=90.0,
            advantage=5,
            mttd_diff_pct=10.0,
        )
        gaps = gap_analysis(metrics)
        assert gaps["all_targets_met"] is True


class TestConfusionMatrixReport:
    def test_report_contains_matrix(self, sample_confusion_matrix):
        metrics = TuningMetrics(
            coverage=80.0,
            precision=80.0,
            advantage=2,
            mttd_khainet_seconds=15.0,
            mttd_darktrace_seconds=20.0,
            mttd_diff_pct=-25.0,
            confusion_matrix=sample_confusion_matrix,
        )
        report = generate_confusion_matrix_report(sample_confusion_matrix, metrics)
        assert "Confusion Matrix" in report
        assert "TP" in report
        assert "FP" in report
        assert "FN" in report
        assert "TN" in report
        assert "Coverage" in report
        assert "Precision" in report
        assert "Advantage" in report
        assert "MTTD" in report

    def test_report_markdown_format(self, sample_confusion_matrix):
        metrics = TuningMetrics(coverage=90.0, precision=85.0, advantage=1)
        report = generate_confusion_matrix_report(sample_confusion_matrix, metrics)
        assert report.startswith("# ")
        assert "|" in report  # Markdown table
