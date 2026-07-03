"""Metrics calculator: the 4 KPIs + confusion matrix for KhaiNet vs Darktrace.

**Corrected definitions** (per architect review):

1. **Cobertura (Coverage)** = TP_KhaiNet / total_incidentes_DT
   → % of incidents that Darktrace detects AND KhaiNet also detects.

2. **Precisión (Precision)** = TP_KhaiNet / (TP_KhaiNet + FP_KhaiNet)
   → % of KhaiNet alerts that are true positives.

3. **Ventaja (Advantage)** = incidents KhaiNet detects that Darktrace doesn't
   → ≥ 0 is the objective (KhaiNet should detect at least as much as DT).

4. **Latencia (MTTD)** = Mean Time To Detect
   → KhaiNet MTTD vs Darktrace MTTD (±30% is the objective).

Confusion matrix layout:
                    Darktrace detecta    Darktrace no detecta
    KhaiNet detecta     TP                   FP (ventaja)
    KhaiNet no detecta  FN (gap cobertura)   TN
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog

from src.models import ConfusionMatrix, TuningMetrics

log = structlog.get_logger()

# Default targets (from config)
DEFAULT_TARGETS: dict[str, float] = {
    "coverage": 90.0,
    "precision": 85.0,
    "advantage": 0.0,
    "latency_diff_pct": 30.0,
}


def calculate_confusion_matrix(
    predictions: list[bool] | np.ndarray,
    labels: list[bool] | np.ndarray,
) -> ConfusionMatrix:
    """Calculate a 2×2 confusion matrix.

    Args:
        predictions: KhaiNet predictions (True=detected).
        labels: Darktrace labels (True=Darktrace detected).

    Returns:
        ConfusionMatrix with TP, FP, FN, TN.
    """
    pred_arr = np.asarray(predictions, dtype=bool)
    label_arr = np.asarray(labels, dtype=bool)

    tp = int(np.sum(label_arr & pred_arr))  # Both detect
    fp = int(np.sum(~label_arr & pred_arr))  # KhaiNet detects, DT doesn't (advantage)
    fn = int(np.sum(label_arr & ~pred_arr))  # DT detects, KhaiNet doesn't (gap)
    tn = int(np.sum(~label_arr & ~pred_arr))  # Neither detects
    total = len(pred_arr)

    return ConfusionMatrix(
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=tn,
        total_events=total,
    )


def calculate_metrics(
    khainet_predictions: list[bool] | np.ndarray,
    darktrace_labels: list[bool] | np.ndarray,
    khainet_latencies: list[float] | np.ndarray | None = None,
    darktrace_latencies: list[float] | np.ndarray | None = None,
) -> TuningMetrics:
    """Calculate the 4 KPIs and confusion matrix.

    Args:
        khainet_predictions: KhaiNet detection predictions (True=anomaly).
        darktrace_labels: Darktrace ground-truth labels (True=anomaly).
        khainet_latencies: KhaiNet detection latencies (seconds).
        darktrace_latencies: Darktrace detection latencies (seconds).

    Returns:
        TuningMetrics with all 4 KPIs and confusion matrix.
    """
    cm = calculate_confusion_matrix(khainet_predictions, darktrace_labels)

    # Coverage: TP_KhaiNet / total_incidentes_DT
    # total_incidentes_DT = TP + FN (all incidents Darktrace detected)
    total_dt_incidents = cm.true_positive + cm.false_negative
    coverage = (
        (cm.true_positive / total_dt_incidents * 100.0)
        if total_dt_incidents > 0
        else 0.0
    )

    # Precision: TP / (TP + FP)
    total_khainet_alerts = cm.true_positive + cm.false_positive
    precision = (
        (cm.true_positive / total_khainet_alerts * 100.0)
        if total_khainet_alerts > 0
        else 0.0
    )

    # Advantage: incidents KhaiNet detects that DT doesn't = FP in this context
    advantage = cm.false_positive

    # MTTD (Mean Time To Detect)
    mttd_khainet = float(np.mean(khainet_latencies)) if khainet_latencies else 0.0
    mttd_darktrace = float(np.mean(darktrace_latencies)) if darktrace_latencies else 0.0

    # MTTD difference percentage
    if mttd_darktrace > 0:
        mttd_diff_pct = (mttd_khainet - mttd_darktrace) / mttd_darktrace * 100.0
    else:
        mttd_diff_pct = 0.0

    metrics = TuningMetrics(
        coverage=coverage,
        precision=precision,
        advantage=advantage,
        mttd_khainet_seconds=mttd_khainet,
        mttd_darktrace_seconds=mttd_darktrace,
        mttd_diff_pct=mttd_diff_pct,
        confusion_matrix=cm,
    )

    log.info(
        "metrics_calculated",
        coverage=coverage,
        precision=precision,
        advantage=advantage,
        mttd_khainet=mttd_khainet,
        mttd_darktrace=mttd_darktrace,
        mttd_diff_pct=mttd_diff_pct,
        tp=cm.true_positive,
        fp=cm.false_positive,
        fn=cm.false_negative,
        tn=cm.true_negative,
    )
    return metrics


def gap_analysis(
    metrics: TuningMetrics,
    targets: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Compare metrics against targets and identify gaps.

    Args:
        metrics: Calculated TuningMetrics.
        targets: Target values (defaults from config).

    Returns:
        Dict with per-metric gap analysis: met, target, actual, gap.
    """
    t = targets or DEFAULT_TARGETS

    coverage_met = metrics.coverage >= t["coverage"]
    precision_met = metrics.precision >= t["precision"]
    advantage_met = metrics.advantage >= t["advantage"]
    latency_met = abs(metrics.mttd_diff_pct) <= t["latency_diff_pct"]

    result: dict[str, Any] = {
        "coverage": {
            "target": t["coverage"],
            "actual": metrics.coverage,
            "gap": t["coverage"] - metrics.coverage,
            "met": coverage_met,
        },
        "precision": {
            "target": t["precision"],
            "actual": metrics.precision,
            "gap": t["precision"] - metrics.precision,
            "met": precision_met,
        },
        "advantage": {
            "target": t["advantage"],
            "actual": metrics.advantage,
            "gap": t["advantage"] - metrics.advantage,
            "met": advantage_met,
        },
        "latency": {
            "target": t["latency_diff_pct"],
            "actual": metrics.mttd_diff_pct,
            "gap": abs(metrics.mttd_diff_pct) - t["latency_diff_pct"],
            "met": latency_met,
        },
        "all_targets_met": coverage_met
        and precision_met
        and advantage_met
        and latency_met,
    }

    log.info(
        "gap_analysis_complete",
        all_met=result["all_targets_met"],
        coverage_met=coverage_met,
        precision_met=precision_met,
        advantage_met=advantage_met,
        latency_met=latency_met,
    )
    return result


def generate_confusion_matrix_report(
    matrix: ConfusionMatrix,
    metrics: TuningMetrics,
) -> str:
    """Generate a markdown report of the confusion matrix and metrics.

    Args:
        matrix: Confusion matrix.
        metrics: Tuning metrics.

    Returns:
        Markdown-formatted report string.
    """
    total = matrix.total_predictions or 1

    report = f"""# Confusion Matrix Report

## 2×2 Matrix

|                       | Darktrace detecta | Darktrace no detecta | Total |
|-----------------------|--------------------|-----------------------|-------|
| **KhaiNet detecta**   | TP = {matrix.true_positive:<6}        | FP = {matrix.false_positive:<6} (ventaja)     | {matrix.true_positive + matrix.false_positive} |
| **KhaiNet no detecta**| FN = {matrix.false_negative:<6} (gap) | TN = {matrix.true_negative:<6}              | {matrix.false_negative + matrix.true_negative} |
| **Total**             | {matrix.true_positive + matrix.false_negative:<6}             | {matrix.false_positive + matrix.true_negative:<6}                    | {total} |

## Key Metrics

| Metric       | Value      | Target  | Status |
|--------------|------------|---------|--------|
| Coverage     | {metrics.coverage:.1f}%   | ≥90%    | {"✅" if metrics.coverage >= 90 else "❌"} |
| Precision    | {metrics.precision:.1f}%   | ≥85%    | {"✅" if metrics.precision >= 85 else "❌"} |
| Advantage    | {metrics.advantage}          | ≥0      | {"✅" if metrics.advantage >= 0 else "❌"} |
| MTTD KhaiNet | {metrics.mttd_khainet_seconds:.1f}s    | —       | — |
| MTTD Darktrace| {metrics.mttd_darktrace_seconds:.1f}s   | —       | — |
| MTTD Diff    | {metrics.mttd_diff_pct:+.1f}%   | ±30%    | {"✅" if abs(metrics.mttd_diff_pct) <= 30 else "❌"} |

## Rates

- **TPR (Recall/Coverage)**: {matrix.true_positive / max(matrix.true_positive + matrix.false_negative, 1) * 100:.1f}%
- **FPR**: {matrix.false_positive / max(matrix.false_positive + matrix.true_negative, 1) * 100:.1f}%
- **FNR (Gap)**: {matrix.false_negative / max(matrix.true_positive + matrix.false_negative, 1) * 100:.1f}%
- **Accuracy**: {(matrix.true_positive + matrix.true_negative) / total * 100:.1f}%
"""
    return report
