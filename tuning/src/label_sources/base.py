"""Abstract base class for all label sources.

A label source converts raw alerts/events from a detection component into
WeakLabel objects. Each source implements the ``generate_labels`` method
that takes a list of model events and produces WeakLabels for matching events.

Sources can also produce "standalone" labels (not tied to specific events)
that the temporal alignment module will match to events later.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.models import ModelScore, WeakLabel


class LabelSource(ABC):
    """Abstract base class for a label source (labelling function).

    Each source has:
    - ``name``: unique identifier (suricata, wazuh, misp, brain, analyst, darktrace)
    - ``weight``: default weight in the weak supervisor
    - ``min_confidence``: minimum confidence to emit a label

    Subclasses must implement:
    - ``generate_labels``: produce WeakLabels from raw input data
    - ``match_to_events``: (optional) match labels to model events by IP+time
    """

    def __init__(
        self,
        name: str,
        weight: float = 1.0,
        min_confidence: float = 0.0,
    ) -> None:
        self.name = name
        self.weight = weight
        self.min_confidence = min_confidence

    @abstractmethod
    def generate_labels(self, raw_data: Any) -> list[WeakLabel]:
        """Convert raw source data into WeakLabel objects.

        Args:
            raw_data: Source-specific raw data (alerts, events, IOCs, etc.).

        Returns:
            List of WeakLabel objects with label, confidence, and source set.
        """
        ...

    def match_to_events(
        self,
        labels: list[WeakLabel],
        events: list[ModelScore],
        window_seconds: float = 60.0,
    ) -> list[WeakLabel]:
        """Match standalone labels to model events by IP + temporal proximity.

        Default implementation: for each label, find the closest event
        (by time) with matching src_ip + dst_ip within the window.
        Labels that don't match any event are discarded.

        Args:
            labels: WeakLabels to match.
            events: Model events to match against.
            window_seconds: Maximum time window for matching.

        Returns:
            Filtered list of WeakLabels with event_id set to matched events.
        """
        # Index events by (src_ip, dst_ip)
        event_index: dict[tuple[str, str], list[ModelScore]] = {}
        for evt in events:
            key = (evt.src_ip, evt.dst_ip)
            event_index.setdefault(key, []).append(evt)

        matched: list[WeakLabel] = []
        for lbl in labels:
            key = (lbl.src_ip, lbl.dst_ip)
            candidates = event_index.get(key, [])

            best_event: ModelScore | None = None
            best_distance = float("inf")

            for evt in candidates:
                distance = abs(evt.ts_epoch - lbl.ts_epoch)
                if distance <= window_seconds and distance < best_distance:
                    best_distance = distance
                    best_event = evt

            if best_event is not None:
                # Set the event_id to the matched event
                matched_label = lbl.model_copy(update={"event_id": best_event.event_id})
                matched.append(matched_label)

        return matched

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, weight={self.weight})"
