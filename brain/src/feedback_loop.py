"""Feedback loop for KhaiNet Brain.

Ingests responses from SOC analysts and Shuffle to improve future correlations:
- Analyst marks FP → register pattern for future filtering
- Analyst confirms TP → reinforce correlation pattern
- Shuffle executes playbook → record result for metrics
- Analyst adjusts severity → record for scorer calibration
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from src.models import AnalystFeedback, FeedbackVerdict

log = structlog.get_logger()


def _safe_eval(data: Any) -> dict[str, Any]:
    """Safely parse a stored pattern dict from Redis.

    Patterns are stored as JSON strings in Redis. This function handles
    JSON strings, raw dicts, and bytes for backward compatibility.
    """
    if isinstance(data, dict):
        return data
    if isinstance(data, (str, bytes)):
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {"raw": data}
    return {"raw": str(data)}


class FeedbackLoop:
    """Processes analyst and Shuffle feedback to improve correlations."""

    def __init__(self, redis_client: Any = None) -> None:
        self.redis = redis_client
        self._local_fp_patterns: list[dict[str, Any]] = []
        self._local_tp_patterns: list[dict[str, Any]] = []
        self._local_severity_calibrations: list[dict[str, Any]] = []

    async def ingest_feedback(self, feedback: AnalystFeedback) -> None:
        """Process feedback from an analyst or Shuffle.

        Depending on the verdict:
        - false_positive: register the FP pattern for future filtering
        - true_positive: reinforce the correlation pattern
        - needs_review: log for manual review
        Also records severity adjustments for scorer calibration.
        """
        log.info(
            "feedback_received",
            feedback_id=feedback.feedback_id,
            incident_id=feedback.incident_id,
            verdict=feedback.verdict,
            analyst=feedback.analyst,
        )

        verdict_val = (
            feedback.verdict
            if isinstance(feedback.verdict, str)
            else feedback.verdict.value
        )

        if verdict_val == FeedbackVerdict.FALSE_POSITIVE.value:
            await self.register_fp_pattern(feedback.incident_id, feedback.reason)
        elif verdict_val == FeedbackVerdict.TRUE_POSITIVE.value:
            await self.reinforce_pattern(feedback.incident_id)
        elif verdict_val == FeedbackVerdict.NEEDS_REVIEW.value:
            log.info(
                "feedback_needs_review",
                incident_id=feedback.incident_id,
                reason=feedback.reason,
            )

        if feedback.severity_adjustment is not None:
            await self.record_severity_calibration(
                feedback.incident_id,
                feedback.original_severity,
                feedback.adjusted_severity,
                feedback.severity_adjustment,
            )

    async def register_fp_pattern(self, incident_id: str, reason: str) -> None:
        """Register a false positive pattern for future filtering."""
        pattern = {
            "incident_id": incident_id,
            "reason": reason,
        }
        if self.redis is not None:
            await self.redis.lpush("brain:fp_patterns", json.dumps(pattern))
        else:
            self._local_fp_patterns.append(pattern)
        log.info("fp_pattern_registered", incident_id=incident_id, reason=reason)

    async def reinforce_pattern(self, incident_id: str) -> None:
        """Reinforce a true positive correlation pattern."""
        pattern = {"incident_id": incident_id}
        if self.redis is not None:
            await self.redis.lpush("brain:tp_patterns", json.dumps(pattern))
        else:
            self._local_tp_patterns.append(pattern)
        log.info("tp_pattern_reinforced", incident_id=incident_id)

    async def record_severity_calibration(
        self,
        incident_id: str,
        original_severity: int | None,
        adjusted_severity: int | None,
        adjustment: int | None,
    ) -> None:
        """Record a severity adjustment for scorer calibration."""
        calibration = {
            "incident_id": incident_id,
            "original_severity": original_severity,
            "adjusted_severity": adjusted_severity,
            "adjustment": adjustment,
        }
        if self.redis is not None:
            await self.redis.lpush(
                "brain:severity_calibrations", json.dumps(calibration)
            )
        else:
            self._local_severity_calibrations.append(calibration)
        log.info(
            "severity_calibration_recorded",
            incident_id=incident_id,
            original=original_severity,
            adjusted=adjusted_severity,
            adjustment=adjustment,
        )

    async def get_fp_patterns(self) -> list[dict[str, Any]]:
        """Get registered FP patterns."""
        if self.redis is not None:
            raw = await self.redis.lrange("brain:fp_patterns", 0, -1)
            return [_safe_eval(r) for r in raw]
        return list(self._local_fp_patterns)

    async def get_tp_patterns(self) -> list[dict[str, Any]]:
        """Get reinforced TP patterns."""
        if self.redis is not None:
            raw = await self.redis.lrange("brain:tp_patterns", 0, -1)
            return [_safe_eval(r) for r in raw]
        return list(self._local_tp_patterns)

    async def get_severity_calibrations(self) -> list[dict[str, Any]]:
        """Get severity calibration records."""
        if self.redis is not None:
            raw = await self.redis.lrange("brain:severity_calibrations", 0, -1)
            return [_safe_eval(r) for r in raw]
        return list(self._local_severity_calibrations)
