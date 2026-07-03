"""Tests for the cost matrix."""

from __future__ import annotations

import numpy as np
import pytest

from src.cost_matrix import CostMatrix


class TestCostMatrixDefaults:
    def test_default_costs(self):
        cm = CostMatrix()
        assert cm.fn_cost == 10.0
        assert cm.fp_cost == 1.0
        assert cm.tp_benefit == 0.0
        assert cm.tn_benefit == 0.0

    def test_custom_costs(self):
        cm = CostMatrix(fn_cost=50.0, fp_cost=5.0, tp_benefit=2.0, tn_benefit=1.0)
        assert cm.fn_cost == 50.0
        assert cm.fp_cost == 5.0
        assert cm.tp_benefit == 2.0
        assert cm.tn_benefit == 1.0


class TestCalculateCost:
    def test_all_correct_no_benefit(self):
        cm = CostMatrix()
        # TP=10, TN=90, no FP, no FN → cost = 0 (no penalty, no benefit)
        cost = cm.calculate_cost(tp=10, fp=0, fn=0, tn=90)
        assert cost == 0.0

    def test_false_negative_penalized(self):
        cm = CostMatrix()
        # 1 FN costs 10
        cost = cm.calculate_cost(tp=0, fp=0, fn=1, tn=99)
        assert cost == -10.0

    def test_false_positive_penalized(self):
        cm = CostMatrix()
        # 1 FP costs 1
        cost = cm.calculate_cost(tp=0, fp=1, fn=0, tn=99)
        assert cost == -1.0

    def test_fn_more_expensive_than_fp(self):
        cm = CostMatrix()
        cost_fn = cm.calculate_cost(tp=0, fp=0, fn=1, tn=99)
        cost_fp = cm.calculate_cost(tp=0, fp=1, fn=0, tn=99)
        assert abs(cost_fn) > abs(cost_fp)
        assert abs(cost_fn) == 10 * abs(cost_fp)

    def test_with_benefit(self):
        cm = CostMatrix(tp_benefit=5.0, tn_benefit=1.0, fn_cost=10.0, fp_cost=1.0)
        cost = cm.calculate_cost(tp=10, fp=2, fn=1, tn=87)
        # 10*5 + 87*1 - 2*1 - 1*10 = 50 + 87 - 2 - 10 = 125
        assert cost == 125.0


class TestCostWeightedScore:
    def test_perfect_predictions(self):
        cm = CostMatrix()
        y_true = [True, True, False, False]
        y_pred = [True, True, False, False]
        score = cm.cost_weighted_score(y_true, y_pred)
        assert score == 0.0  # No penalties

    def test_with_false_negatives(self):
        cm = CostMatrix()
        y_true = [True, True, False]
        y_pred = [False, False, False]  # 2 FN
        score = cm.cost_weighted_score(y_true, y_pred)
        assert score == -20.0  # 2 * 10

    def test_with_false_positives(self):
        cm = CostMatrix()
        y_true = [False, False, True]
        y_pred = [True, True, True]  # 2 FP, 1 TP
        score = cm.cost_weighted_score(y_true, y_pred)
        assert score == -2.0  # 2 * 1

    def test_numpy_arrays(self):
        cm = CostMatrix()
        y_true = np.array([True, False, True])
        y_pred = np.array([True, True, False])
        score = cm.cost_weighted_score(y_true, y_pred)
        # TP=1, FP=1, FN=1 → 0 - 1 - 10 = -11
        assert score == -11.0


class TestCostAtThreshold:
    def test_threshold_zero_all_positive(self):
        cm = CostMatrix()
        scores = [0.1, 0.5, 0.9]
        labels = [False, True, True]
        # threshold=0 → all predicted positive: TP=2, FP=1
        cost = cm.cost_at_threshold(scores, labels, 0.0)
        assert cost == -1.0  # 1 FP

    def test_threshold_one_all_negative(self):
        cm = CostMatrix()
        scores = [0.1, 0.5, 0.9]
        labels = [False, True, True]
        # threshold=1.0 → all predicted negative: FN=2
        cost = cm.cost_at_threshold(scores, labels, 1.0)
        assert cost == -20.0  # 2 FN


class TestFindOptimalThreshold:
    def test_optimal_threshold_in_range(self):
        cm = CostMatrix()
        # Clear separation: normals < 0.3, anomalies > 0.7
        scores = [0.1, 0.15, 0.2, 0.25, 0.75, 0.8, 0.85, 0.9]
        labels = [False, False, False, False, True, True, True, True]
        threshold, cost = cm.find_optimal_threshold(scores, labels)
        assert 0.0 < threshold < 1.0
        # Optimal should be between 0.25 and 0.75
        assert 0.25 < threshold < 0.75

    def test_optimal_minimizes_fn(self):
        """With FN 10x more expensive, optimal threshold should be low
        to avoid missing anomalies."""
        cm = CostMatrix(fn_cost=10.0, fp_cost=1.0)
        scores = [0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9]
        labels = [False, False, False, False, True, True, True, True]
        threshold, _ = cm.find_optimal_threshold(scores, labels)
        # Should lean towards lower threshold to catch all anomalies
        assert threshold <= 0.6

    def test_custom_thresholds(self):
        cm = CostMatrix()
        scores = [0.1, 0.5, 0.9]
        labels = [False, True, True]
        custom = [0.3, 0.6, 0.8]
        threshold, cost = cm.find_optimal_threshold(scores, labels, thresholds=custom)
        assert threshold in custom
