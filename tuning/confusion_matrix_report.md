# Confusion Matrix Report

## 2×2 Matrix

|                       | Darktrace detecta | Darktrace no detecta | Total |
|-----------------------|--------------------|-----------------------|-------|
| **KhaiNet detecta**   | TP = 25            | FP = 0      (ventaja)     | 25 |
| **KhaiNet no detecta**| FN = 0      (gap) | TN = 475                 | 475 |
| **Total**             | 25                 | 475                       | 500 |

## Key Metrics

| Metric       | Value      | Target  | Status |
|--------------|------------|---------|--------|
| Coverage     | 100.0%   | ≥90%    | ✅ |
| Precision    | 100.0%   | ≥85%    | ✅ |
| Advantage    | 0          | ≥0      | ✅ |
| MTTD KhaiNet | 8.6s    | —       | — |
| MTTD Darktrace| 7.3s   | —       | — |
| MTTD Diff    | +17.8%   | ±30%    | ✅ |

## Rates

- **TPR (Recall/Coverage)**: 100.0%
- **FPR**: 0.0%
- **FNR (Gap)**: 0.0%
- **Accuracy**: 100.0%
