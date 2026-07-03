"""Tests for the weak supervisor (multi-source label combination)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.label_sources import (
    AnalystLabeler,
    BrainLabeler,
    MISPLabeler,
    SuricataLabeler,
    WazuhLabeler,
)
from src.models import (
    AnalystFeedback,
    BrainCorrelation,
    MISPEvent,
    ModelScore,
    SuricataAlert,
    WazuhAlert,
    WeakLabel,
)
from src.synthetic_data import generate_auto_labeling_dataset
from src.weak_supervisor import WeakSupervisor


class TestWeakSupervisorCombine:
    """Test the combine_labels method with pre-built WeakLabels."""

    def test_single_positive_source(self, now_utc, src_ip_a, dst_ip_a):
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=True,
                confidence=0.9,
            ),
        ]
        supervisor = WeakSupervisor(sources=[SuricataLabeler()])
        consensus = supervisor.combine_labels(labels)
        assert len(consensus) == 1
        assert consensus[0].label is True
        assert consensus[0].confidence > 0

    def test_multiple_sources_agree(self, now_utc, src_ip_a, dst_ip_a):
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=True,
                confidence=0.9,
            ),
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="misp",
                label=True,
                confidence=0.85,
            ),
        ]
        supervisor = WeakSupervisor(sources=[SuricataLabeler(), MISPLabeler()])
        consensus = supervisor.combine_labels(labels)
        assert len(consensus) == 1
        assert consensus[0].label is True
        assert consensus[0].votes_positive == 2
        assert "suricata" in consensus[0].contributing_sources
        assert "misp" in consensus[0].contributing_sources

    def test_analyst_override(self, now_utc, src_ip_a, dst_ip_a):
        """Analyst label should override other sources."""
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=True,
                confidence=0.9,
            ),
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc + timedelta(seconds=1),
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="analyst",
                label=False,  # analyst says it's NOT an anomaly
                confidence=1.0,
            ),
        ]
        supervisor = WeakSupervisor(
            sources=[SuricataLabeler(), AnalystLabeler()],
            analyst_override=True,
        )
        consensus = supervisor.combine_labels(labels)
        assert len(consensus) == 1
        assert consensus[0].label is False  # analyst override
        assert consensus[0].confidence == 1.0

    def test_no_analyst_override_disabled(self, now_utc, src_ip_a, dst_ip_a):
        """When analyst_override=False, analyst is just another vote."""
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=True,
                confidence=0.9,
            ),
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="analyst",
                label=False,
                confidence=1.0,
            ),
        ]
        supervisor = WeakSupervisor(
            sources=[SuricataLabeler(weight=1.2), AnalystLabeler(weight=2.0)],
            analyst_override=False,
        )
        consensus = supervisor.combine_labels(labels)
        assert len(consensus) == 1
        # Weighted: suricata 1.2*0.9=1.08 positive vs analyst 2.0*1.0=2.0 negative
        # score = (1.08 - 2.0) / (1.08 + 2.0) = -0.92/3.08 = -0.299
        assert consensus[0].label is False  # analyst wins by weight

    def test_all_sources_abstain(self, now_utc, src_ip_a, dst_ip_a):
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=None,  # abstain
                confidence=0.5,
            ),
        ]
        supervisor = WeakSupervisor(sources=[SuricataLabeler()])
        consensus = supervisor.combine_labels(labels)
        assert len(consensus) == 0  # no consensus when all abstain

    def test_multiple_events(self, now_utc, src_ip_a, dst_ip_a):
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=True,
                confidence=0.9,
            ),
            WeakLabel(
                event_id="evt-2",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="misp",
                label=False,
                confidence=0.8,
            ),
        ]
        supervisor = WeakSupervisor(sources=[SuricataLabeler(), MISPLabeler()])
        consensus = supervisor.combine_labels(labels)
        assert len(consensus) == 2
        labels_by_id = {c.event_id: c for c in consensus}
        assert labels_by_id["evt-1"].label is True
        assert labels_by_id["evt-2"].label is False


class TestWeakSupervisorPipeline:
    """Test the full label_events pipeline with source data."""

    def test_label_events_with_synthetic_data(self):
        """Full pipeline: generate dataset → label events with all sources."""
        dataset = generate_auto_labeling_dataset(
            n_events=200, anomaly_ratio=0.1, seed=42
        )

        sources = [
            SuricataLabeler(),
            WazuhLabeler(),
            MISPLabeler(),
            BrainLabeler(),
            AnalystLabeler(),
        ]
        supervisor = WeakSupervisor(sources=sources)

        source_data = {
            "suricata": dataset["suricata"],
            "wazuh": dataset["wazuh"],
            "misp": dataset["misp"],
            "brain": dataset["brain"],
            "analyst": dataset["analyst"],
        }

        consensus = supervisor.label_events(
            events=dataset["events"],
            source_data=source_data,
            window_seconds=60.0,
        )

        # Should have some consensus labels
        assert len(consensus) > 0
        for cl in consensus:
            assert 0.0 <= cl.confidence <= 1.0
            assert cl.source == "weak_supervision"

    def test_get_unlabeled_events(self):
        """Events without any source vote should be returned as unlabeled."""
        dataset = generate_auto_labeling_dataset(
            n_events=100, anomaly_ratio=0.1, seed=42
        )

        sources = [SuricataLabeler(), BrainLabeler()]
        supervisor = WeakSupervisor(sources=sources)

        source_data = {
            "suricata": dataset["suricata"],
            "brain": dataset["brain"],
        }

        consensus = supervisor.label_events(
            events=dataset["events"],
            source_data=source_data,
            window_seconds=60.0,
        )

        unlabeled = supervisor.get_unlabeled_events(dataset["events"], consensus)
        # Some events should be unlabeled (not all events match source alerts)
        assert len(unlabeled) > 0
        assert len(unlabeled) + len(consensus) <= len(dataset["events"])

    def test_source_statistics(self, now_utc, src_ip_a, dst_ip_a):
        labels = [
            WeakLabel(
                event_id="evt-1",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=True,
                confidence=0.9,
            ),
            WeakLabel(
                event_id="evt-2",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="suricata",
                label=False,
                confidence=0.8,
            ),
            WeakLabel(
                event_id="evt-3",
                timestamp=now_utc,
                src_ip=src_ip_a,
                dst_ip=dst_ip_a,
                source="misp",
                label=True,
                confidence=0.95,
            ),
        ]
        supervisor = WeakSupervisor(sources=[SuricataLabeler(), MISPLabeler()])
        stats = supervisor.get_source_statistics(labels)

        assert "suricata" in stats
        assert stats["suricata"]["count"] == 2
        assert stats["suricata"]["positive"] == 1
        assert stats["suricata"]["negative"] == 1
        assert "misp" in stats
        assert stats["misp"]["count"] == 1
        assert stats["misp"]["positive"] == 1


class TestConsensusLabelConversion:
    """Test that ConsensusLabel can convert to SupervisedLabel."""

    def test_to_supervised_label(self, now_utc, src_ip_a, dst_ip_a):
        from src.models import ConsensusLabel

        cl = ConsensusLabel(
            event_id="evt-1",
            timestamp=now_utc,
            src_ip=src_ip_a,
            dst_ip=dst_ip_a,
            label=True,
            confidence=0.85,
            source="weak_supervision",
            contributing_sources=["suricata", "misp"],
        )
        sl = cl.to_supervised_label()
        assert sl.label is True
        assert sl.confidence == 0.85
        assert sl.source == "weak_supervision"
