"""Temporal alignment: match supervised labels to model events.

This is the most critical module in the tuning pipeline (identified by the
architect as the #1 failure point). It matches Darktrace labels to KhaiNet
model events based on:

1. **Temporal proximity**: the label and event timestamps must be within
   ``window_seconds`` of each other (with optional ``jitter_seconds``
   tolerance).
2. **IP matching**: ``src_ip`` and ``dst_ip`` must match exactly.

Algorithm:
    For each event, find the closest label (by absolute time distance) that
    matches on src_ip + dst_ip and is within the time window. If multiple
    labels match, pick the temporally closest. If no label matches, the
    event is labeled ``False`` (normal) by default.

Edge cases handled:
    - Events with no matching label → label=False, confidence=0
    - Labels with no matching event → ignored (not in output)
    - Duplicate labels → only the closest is used per event
    - IPs that don't match → no match
    - Window exceeded → no match
"""

from __future__ import annotations

from datetime import datetime

import structlog

from src.models import AlignedEvent, ModelScore, SupervisedLabel

log = structlog.get_logger()


def _time_diff_seconds(a: datetime, b: datetime) -> float:
    """Absolute time difference in seconds between two datetimes."""
    return abs((a - b).total_seconds())


def _match_confidence(
    distance_seconds: float,
    window_seconds: float,
    jitter_seconds: float,
) -> float:
    """Calculate match confidence based on temporal distance.

    Confidence is 1.0 at distance=0 and decreases linearly to 0.0 at
    ``window_seconds + jitter_seconds``.

    Args:
        distance_seconds: Absolute time difference.
        window_seconds: Primary matching window.
        jitter_seconds: Additional jitter tolerance.

    Returns:
        Confidence in [0.0, 1.0].
    """
    max_distance = window_seconds + jitter_seconds
    if max_distance <= 0:
        return 1.0 if distance_seconds == 0 else 0.0
    confidence = 1.0 - (distance_seconds / max_distance)
    return max(0.0, min(1.0, confidence))


def align_labels_to_events(
    labels: list[SupervisedLabel],
    events: list[ModelScore],
    window_seconds: float = 60.0,
    jitter_seconds: float = 30.0,
) -> list[AlignedEvent]:
    """Align supervised labels to model events via temporal + IP matching.

    For each event, searches for the closest matching label (by time) that
    shares the same src_ip and dst_ip and falls within the time window.
    Events without a match get label=False (normal).

    Args:
        labels: Supervised labels from Darktrace.
        events: Model scores from KhaiNet detectors.
        window_seconds: Maximum time window for matching.
        jitter_seconds: Additional jitter tolerance beyond the window.

    Returns:
        List of AlignedEvent, one per input event, in the same order.
    """
    max_distance = window_seconds + jitter_seconds

    # Index labels by (src_ip, dst_ip) for efficient lookup
    label_index: dict[tuple[str, str], list[SupervisedLabel]] = {}
    for lbl in labels:
        key = (lbl.src_ip, lbl.dst_ip)
        label_index.setdefault(key, []).append(lbl)

    aligned: list[AlignedEvent] = []
    matched_label_ids: set[str] = set()

    for event in events:
        key = (event.src_ip, event.dst_ip)
        candidates = label_index.get(key, [])

        best_label: SupervisedLabel | None = None
        best_distance = float("inf")

        for lbl in candidates:
            distance = _time_diff_seconds(event.timestamp, lbl.timestamp)
            if distance <= max_distance and distance < best_distance:
                best_distance = distance
                best_label = lbl

        if best_label is not None:
            confidence = _match_confidence(
                best_distance, window_seconds, jitter_seconds
            )
            aligned.append(
                AlignedEvent(
                    event=event,
                    label=best_label.label,
                    match_distance_seconds=best_distance,
                    match_confidence=confidence,
                    matched_label_id=best_label.event_id,
                )
            )
            matched_label_ids.add(best_label.event_id)
        else:
            # No match found → default to normal (False)
            aligned.append(
                AlignedEvent(
                    event=event,
                    label=False,
                    match_distance_seconds=None,
                    match_confidence=0.0,
                    matched_label_id=None,
                )
            )

    unmatched_labels = len(labels) - len(matched_label_ids)
    log.debug(
        "alignment_complete",
        n_events=len(events),
        n_labels=len(labels),
        n_matched=len(matched_label_ids),
        n_unmatched_labels=unmatched_labels,
        window_seconds=window_seconds,
        jitter_seconds=jitter_seconds,
    )
    return aligned


def alignment_summary(aligned_events: list[AlignedEvent]) -> dict[str, int | float]:
    """Return a summary of the alignment results.

    Args:
        aligned_events: Output of ``align_labels_to_events``.

    Returns:
        Dict with match statistics.
    """
    total = len(aligned_events)
    matched = sum(1 for a in aligned_events if a.matched_label_id is not None)
    unmatched = total - matched
    positive_labels = sum(1 for a in aligned_events if a.label)
    avg_confidence = sum(
        a.match_confidence for a in aligned_events if a.matched_label_id
    ) / max(matched, 1)
    avg_distance = sum(
        a.match_distance_seconds
        for a in aligned_events
        if a.match_distance_seconds is not None
    ) / max(matched, 1)
    return {
        "total_events": total,
        "matched": matched,
        "unmatched": unmatched,
        "match_rate": matched / total if total > 0 else 0.0,
        "positive_labels": positive_labels,
        "avg_confidence": avg_confidence,
        "avg_distance_seconds": avg_distance,
    }
