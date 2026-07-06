"""Cross-module imports for detection/ and tuning/.

Both detection/ and tuning/ (and pipeline/ itself) use ``src`` as their
top-level package name. This creates a namespace conflict: only one ``src``
can be active in ``sys.modules`` at a time.

This module provides context managers that temporarily swap ``sys.path``
and ``sys.modules`` so that detection/ or tuning/ modules can be imported
on demand. After the context exits, the pipeline's own ``src`` is restored.

Usage::

    from src.cross_imports import detection_context, tuning_context

    with detection_context():
        from src.orchestrator import DetectionOrchestrator
        orchestrator = DetectionOrchestrator()

    # Later, when calling orchestrator.detect() (which has lazy imports):
    with detection_context():
        results = orchestrator.detect(conn_events, ...)

    with tuning_context():
        from src.weak_supervisor import WeakSupervisor
        supervisor = WeakSupervisor(sources)
"""

from __future__ import annotations

import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# Workspace root: pipeline/src/cross_imports.py → parents[2] = /workspace
_WORKSPACE = Path(__file__).resolve().parents[2]
_DETECTION_ROOT = _WORKSPACE / "detection"
_TUNING_ROOT = _WORKSPACE / "tuning"


def _save_src_modules() -> dict[str, Any]:
    """Save and remove all 'src' entries from sys.modules.

    Returns a dict of the saved modules so they can be restored later.
    """
    saved: dict[str, Any] = {}
    for key in list(sys.modules):
        if key == "src" or key.startswith("src."):
            saved[key] = sys.modules.pop(key)
    return saved


def _clear_src_modules() -> None:
    """Remove all 'src' entries from sys.modules."""
    for key in list(sys.modules):
        if key == "src" or key.startswith("src."):
            sys.modules.pop(key, None)


@contextmanager
def detection_context() -> Generator[None, None, None]:
    """Temporarily swap sys.path/modules to detection/'s src package.

    Within this context, ``from src.xxx import`` resolves to detection/src/.
    After the context exits, the pipeline's own ``src`` is restored.

    Yields:
        None
    """
    root_str = str(_DETECTION_ROOT)
    saved_modules = _save_src_modules()
    saved_path = list(sys.path)

    if root_str in sys.path:
        sys.path.remove(root_str)
    sys.path.insert(0, root_str)

    try:
        yield
    finally:
        sys.path[:] = saved_path
        _clear_src_modules()
        sys.modules.update(saved_modules)


@contextmanager
def tuning_context() -> Generator[None, None, None]:
    """Temporarily swap sys.path/modules to tuning/'s src package.

    Within this context, ``from src.xxx import`` resolves to tuning/src/.
    After the context exits, the pipeline's own ``src`` is restored.

    Yields:
        None
    """
    root_str = str(_TUNING_ROOT)
    saved_modules = _save_src_modules()
    saved_path = list(sys.path)

    if root_str in sys.path:
        sys.path.remove(root_str)
    sys.path.insert(0, root_str)

    try:
        yield
    finally:
        sys.path[:] = saved_path
        _clear_src_modules()
        sys.modules.update(saved_modules)


# ---------------------------------------------------------------------------
# Convenience loaders (each wraps the appropriate context manager)
# ---------------------------------------------------------------------------


def create_detection_orchestrator(
    config: dict[str, Any] | None = None,
) -> Any:
    """Create a DetectionOrchestrator from detection/src/orchestrator.py.

    Args:
        config: Optional configuration dict for the orchestrator.

    Returns:
        A DetectionOrchestrator instance.
    """
    with detection_context():
        from src.orchestrator import DetectionOrchestrator

        return DetectionOrchestrator(config)


def generate_synthetic_zeek_logs(
    log_type: str,
    n_events: int = 1,
    anomaly_ratio: float = 0.0,
    seed: int | None = None,
) -> list[Any]:
    """Generate synthetic Zeek log events using detection/synthetic_data.py.

    Args:
        log_type: One of 'conn', 'dns', 'http', 'ssl'.
        n_events: Number of events to generate.
        anomaly_ratio: Fraction of anomalies (0.0 = all normal, 1.0 = all anomaly).
        seed: Random seed.

    Returns:
        List of Zeek Pydantic model instances (ZeekConn, ZeekDNS, etc.).
    """
    import random

    actual_seed = seed if seed is not None else random.randint(0, 1_000_000)

    with detection_context():
        if log_type == "conn":
            from src.synthetic_data import generate_zeek_conn_logs

            return generate_zeek_conn_logs(
                n_events=n_events, anomaly_ratio=anomaly_ratio, seed=actual_seed
            )
        elif log_type == "dns":
            from src.synthetic_data import generate_zeek_dns_logs

            return generate_zeek_dns_logs(
                n_events=n_events, anomaly_ratio=anomaly_ratio, seed=actual_seed
            )
        elif log_type == "http":
            from src.synthetic_data import generate_zeek_http_logs

            return generate_zeek_http_logs(
                n_events=n_events, anomaly_ratio=anomaly_ratio, seed=actual_seed
            )
        elif log_type == "ssl":
            from src.synthetic_data import generate_zeek_ssl_logs

            return generate_zeek_ssl_logs(
                n_events=n_events, anomaly_ratio=anomaly_ratio, seed=actual_seed
            )
        else:
            raise ValueError(f"Unknown log type: {log_type}")


def get_detection_model_classes() -> dict[str, type]:
    """Get Pydantic model classes from detection/src/models.py.

    Must be called within detection_context() or use the returned references
    directly (they remain valid after the context exits).

    Returns:
        Dict with keys: ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL, ModelResult.
    """
    with detection_context():
        from src.models import ModelResult, ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL

        return {
            "ZeekConn": ZeekConn,
            "ZeekDNS": ZeekDNS,
            "ZeekHTTP": ZeekHTTP,
            "ZeekSSL": ZeekSSL,
            "ModelResult": ModelResult,
        }


def create_tuning_labelers() -> dict[str, Any]:
    """Create label source instances from tuning/src/label_sources/.

    Returns:
        Dict mapping source name → labeler instance.
    """
    with tuning_context():
        from src.label_sources import (
            AnalystLabeler,
            MISPLabeler,
            SuricataLabeler,
            WazuhLabeler,
        )

        return {
            "suricata": SuricataLabeler(),
            "wazuh": WazuhLabeler(),
            "misp": MISPLabeler(),
            "analyst": AnalystLabeler(),
        }


def create_weak_supervisor(
    sources: list[Any] | None = None,
    decision_threshold: float = 0.0,
    abstain_threshold: float = 0.0,
) -> Any:
    """Create a WeakSupervisor from tuning/src/weak_supervisor.py.

    Args:
        sources: List of LabelSource instances. If None, creates default sources.
        decision_threshold: Score above which label is True.
        abstain_threshold: Below this absolute score, supervisor abstains.

    Returns:
        A WeakSupervisor instance.
    """
    with tuning_context():
        from src.weak_supervisor import WeakSupervisor

        if sources is None:
            from src.label_sources import (
                AnalystLabeler,
                MISPLabeler,
                SuricataLabeler,
                WazuhLabeler,
            )

            sources = [
                SuricataLabeler(),
                WazuhLabeler(),
                MISPLabeler(),
                AnalystLabeler(),
            ]

        return WeakSupervisor(
            sources=sources,
            decision_threshold=decision_threshold,
            abstain_threshold=abstain_threshold,
        )


def create_active_learning_selector(
    strategy: str = "hybrid",
    batch_size: int = 20,
) -> Any:
    """Create an ActiveLearningSelector from tuning/src/active_learning.py.

    Args:
        strategy: Selection strategy (uncertainty, disagreement, diversity, hybrid).
        batch_size: Number of events per batch.

    Returns:
        An ActiveLearningSelector instance.
    """
    with tuning_context():
        from src.active_learning import ActiveLearningSelector

        return ActiveLearningSelector(strategy=strategy, batch_size=batch_size)


def get_tuning_model_classes() -> dict[str, type]:
    """Get Pydantic model classes from tuning/src/models.py.

    Returns:
        Dict with keys: SuricataAlert, WazuhAlert, WeakLabel, ConsensusLabel,
        ModelScore, AnalystFeedback, ActiveLearningQuery.
    """
    with tuning_context():
        from src.models import (
            ActiveLearningQuery,
            AnalystFeedback,
            ConsensusLabel,
            ModelScore,
            SuricataAlert,
            WazuhAlert,
            WeakLabel,
        )

        return {
            "SuricataAlert": SuricataAlert,
            "WazuhAlert": WazuhAlert,
            "WeakLabel": WeakLabel,
            "ConsensusLabel": ConsensusLabel,
            "ModelScore": ModelScore,
            "AnalystFeedback": AnalystFeedback,
            "ActiveLearningQuery": ActiveLearningQuery,
        }
