"""Tests for temporal alignment — the most critical module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.models import ModelScore, SupervisedLabel
from src.temporal_alignment import (
    _match_confidence,
    _time_diff_seconds,
    align_labels_to_events,
    alignment_summary,
)


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestTimeDiffSeconds:
    def test_same_time(self):
        t = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
        assert _time_diff_seconds(t, t) == 0.0

    def test_positive_diff(self):
        t1 = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 7, 1, 10, 1, 0, tzinfo=timezone.utc)
        assert _time_diff_seconds(t1, t2) == 60.0

    def test_negative_diff_is_absolute(self):
        t1 = datetime(2026, 7, 1, 10, 1, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
        assert _time_diff_seconds(t1, t2) == 60.0


class TestMatchConfidence:
    def test_zero_distance(self):
        assert _match_confidence(0.0, 60.0, 30.0) == 1.0

    def test_max_distance(self):
        # window + jitter = 90 seconds
        assert _match_confidence(90.0, 60.0, 30.0) == 0.0

    def test_beyond_max(self):
        assert _match_confidence(120.0, 60.0, 30.0) == 0.0

    def test_midpoint(self):
        # At 45 seconds (half of 90), confidence should be 0.5
        conf = _match_confidence(45.0, 60.0, 30.0)
        assert abs(conf - 0.5) < 0.01

    def test_clamped_to_zero(self):
        assert _match_confidence(200.0, 60.0, 30.0) == 0.0


# ---------------------------------------------------------------------------
# Alignment tests
# ---------------------------------------------------------------------------


class TestAlignExactMatch:
    """Label and event at the same timestamp, same IPs."""

    def test_exact_match(self, now_utc, src_ip_a, dst_ip_a):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        label = SupervisedLabel(
            event_id="l1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        aligned = align_labels_to_events([label], [event])
        assert len(aligned) == 1
        assert aligned[0].label is True
        assert aligned[0].match_distance_seconds == 0.0
        assert aligned[0].match_confidence == 1.0
        assert aligned[0].matched_label_id == "l1"


class TestAlignWindowExceeded:
    """Label outside the time window → no match."""

    def test_window_exceeded(self, now_utc, src_ip_a, dst_ip_a):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        # Label 120 seconds away (window=60, jitter=30, max=90)
        label = SupervisedLabel(
            event_id="l1",
            timestamp=now_utc + timedelta(seconds=120),
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        aligned = align_labels_to_events(
            [label], [event], window_seconds=60.0, jitter_seconds=30.0
        )
        assert len(aligned) == 1
        assert aligned[0].label is False
        assert aligned[0].match_distance_seconds is None
        assert aligned[0].match_confidence == 0.0
        assert aligned[0].matched_label_id is None


class TestAlignJitter:
    """Label within window + jitter but outside window."""

    def test_within_jitter(self, now_utc, src_ip_a, dst_ip_a):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        # Label 75 seconds away: window=60, jitter=30 → max=90, so 75 is within
        label = SupervisedLabel(
            event_id="l1",
            timestamp=now_utc + timedelta(seconds=75),
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        aligned = align_labels_to_events(
            [label], [event], window_seconds=60.0, jitter_seconds=30.0
        )
        assert aligned[0].label is True
        assert aligned[0].match_distance_seconds == 75.0
        assert 0.0 < aligned[0].match_confidence < 1.0


class TestAlignMultipleMatches:
    """Multiple labels match → pick the closest in time."""

    def test_closest_match(self, now_utc, src_ip_a, dst_ip_a):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        label_far = SupervisedLabel(
            event_id="l-far",
            timestamp=now_utc + timedelta(seconds=50),
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        label_close = SupervisedLabel(
            event_id="l-close",
            timestamp=now_utc + timedelta(seconds=10),
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        aligned = align_labels_to_events(
            [label_far, label_close], [event], window_seconds=60.0, jitter_seconds=30.0
        )
        assert aligned[0].matched_label_id == "l-close"
        assert aligned[0].match_distance_seconds == 10.0


class TestAlignNoMatch:
    """No labels at all → all events get label=False."""

    def test_no_labels(self, now_utc, src_ip_a, dst_ip_a):
        events = [
            ModelScore(
                event_id=f"e{i}",
                timestamp=now_utc + timedelta(seconds=i),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.5,
            )
            for i in range(5)
        ]
        aligned = align_labels_to_events([], events)
        assert len(aligned) == 5
        for ae in aligned:
            assert ae.label is False
            assert ae.matched_label_id is None


class TestAlignIPsNotMatching:
    """Labels with different IPs → no match."""

    def test_different_ips(self, now_utc, src_ip_a, dst_ip_a, src_ip_b, dst_ip_b):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        label = SupervisedLabel(
            event_id="l1",
            timestamp=now_utc,
            src_ip=src_ip_b,  # Different src
            dst_ip=dst_ip_b,  # Different dst
            label=True,
        )
        aligned = align_labels_to_events([label], [event])
        assert aligned[0].label is False
        assert aligned[0].matched_label_id is None

    def test_only_src_matches(self, now_utc, src_ip_a, dst_ip_a, dst_ip_b):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        label = SupervisedLabel(
            event_id="l1",
            timestamp=now_utc,
            src_ip=src_ip_a,  # Same src
            dst_ip=dst_ip_b,  # Different dst
            label=True,
        )
        aligned = align_labels_to_events([label], [event])
        assert aligned[0].label is False


class TestAlignDuplicateLabels:
    """Duplicate labels (same time, IPs) → only closest used."""

    def test_duplicates(self, now_utc, src_ip_a, dst_ip_a):
        event = ModelScore(
            event_id="e1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            model_name="isolation_forest",
            score=0.9,
        )
        label1 = SupervisedLabel(
            event_id="l1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        label2 = SupervisedLabel(
            event_id="l2",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
        )
        aligned = align_labels_to_events([label1, label2], [event])
        assert aligned[0].label is True
        # One of the two labels should be matched
        assert aligned[0].matched_label_id in ("l1", "l2")


class TestAlignOrderPreserved:
    """Output order matches input event order."""

    def test_order(self, now_utc, src_ip_a, dst_ip_a):
        events = [
            ModelScore(
                event_id=f"e{i}",
                timestamp=now_utc + timedelta(seconds=i * 100),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                model_name="isolation_forest",
                score=0.5 + i * 0.1,
            )
            for i in range(5)
        ]
        aligned = align_labels_to_events([], events)
        assert [ae.event.event_id for ae in aligned] == [
            "e0",
            "e1",
            "e2",
            "e3",
            "e4",
        ]


class TestAlignmentSummary:
    def test_summary(self, sample_aligned_events):
        summary = alignment_summary(sample_aligned_events)
        assert "total_events" in summary
        assert "matched" in summary
        assert "unmatched" in summary
        assert "match_rate" in summary
        assert summary["total_events"] == len(sample_aligned_events)
        assert summary["matched"] + summary["unmatched"] == summary["total_events"]

    def test_empty_summary(self):
        summary = alignment_summary([])
        assert summary["total_events"] == 0
        assert summary["match_rate"] == 0.0
