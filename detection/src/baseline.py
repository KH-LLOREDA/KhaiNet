"""Statistical baseline calculator for network traffic.

Computes per-host and per-service baseline statistics (mean, std, min, max,
percentiles) from Zeek connection and DNS events. Used for:
- HMM state mapping (comparing state means to baseline)
- Anomaly scoring (z-scores, ratio vs p99)
- Dashboard thresholds
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np
import structlog

from src.models import BaselineStats, ZeekConn, ZeekDNS

log = structlog.get_logger()

# Metrics to compute per (src_ip, service)
BASELINE_METRICS = [
    "bytes_out",
    "bytes_in",
    "duration",
    "unique_destinations",
    "unique_ports",
    "pkts_total",
    "dns_queries",
]


class BaselineCalculator:
    """Calculate and store statistical baselines for network traffic.

    Computes per-host and per-service statistics over a configurable time
    window. Supports comparison of individual events against the baseline
    and serialization for persistence.

    Attributes:
        window_hours: Time window for baseline calculation (default 24h).
        stats: List of BaselineStats objects.
        _stats_index: Lookup index for fast access.
    """

    def __init__(self, window_hours: int = 24):
        self.window_hours = window_hours
        self.stats: list[BaselineStats] = []
        self._stats_index: dict[tuple[str, str | None], list[BaselineStats]] = {}

    def calculate_baseline(
        self,
        conn_events: list[ZeekConn],
        dns_events: list[ZeekDNS] | None = None,
    ) -> list[BaselineStats]:
        """Calculate baseline statistics from connection and DNS events.

        For each (src_ip, service) pair, computes:
        - mean, std, min, max, p50, p95, p99 for each metric
        - sample_count

        Metrics: bytes_out, bytes_in, duration, unique_destinations,
                 unique_ports, pkts_total, dns_queries

        Args:
            conn_events: List of Zeek connection events.
            dns_events: List of Zeek DNS events (optional).

        Returns:
            List of BaselineStats objects.
        """
        dns_events = dns_events or []

        # Group conn events by (src_ip, service)
        groups: dict[tuple[str, str | None], list[ZeekConn]] = defaultdict(list)
        for conn in conn_events:
            service = conn.service or "unknown"
            groups[(conn.src_ip, service)].append(conn)

        # Compute DNS aggregates per host
        host_dns: dict[str, int] = defaultdict(int)
        for dns in dns_events:
            host_dns[dns.src_ip] += 1

        # Compute unique destinations and ports per (host, service)
        all_stats: list[BaselineStats] = []

        for (src_ip, service), conns in groups.items():
            if not conns:
                continue

            # Extract metric values
            bytes_out_vals = [c.orig_bytes for c in conns]
            bytes_in_vals = [c.resp_bytes for c in conns]
            duration_vals = [c.duration for c in conns]
            pkts_total_vals = [c.pkts_total for c in conns]
            unique_dsts_vals = [len({c.dst_ip for c in conns})] * len(conns)
            unique_ports_vals = [len({c.dst_port for c in conns})] * len(conns)
            dns_queries_vals = [host_dns.get(src_ip, 0)] * len(conns)

            metric_data = {
                "bytes_out": bytes_out_vals,
                "bytes_in": bytes_in_vals,
                "duration": duration_vals,
                "unique_destinations": unique_dsts_vals,
                "unique_ports": unique_ports_vals,
                "pkts_total": pkts_total_vals,
                "dns_queries": dns_queries_vals,
            }

            for metric_name, values in metric_data.items():
                arr = np.array(values, dtype=np.float64)
                stat = BaselineStats(
                    src_ip=src_ip,
                    service=service,
                    metric=metric_name,
                    mean=float(np.mean(arr)),
                    std=float(np.std(arr)),
                    min_val=float(np.min(arr)),
                    max_val=float(np.max(arr)),
                    p50=float(np.percentile(arr, 50)),
                    p95=float(np.percentile(arr, 95)),
                    p99=float(np.percentile(arr, 99)),
                    sample_count=len(values),
                    window_hours=self.window_hours,
                )
                all_stats.append(stat)

        self.stats = all_stats
        self._build_index()

        log.info(
            "baseline_calculated",
            n_stats=len(all_stats),
            n_hosts=len({s.src_ip for s in all_stats}),
            n_services=len({s.service for s in all_stats}),
        )
        return all_stats

    def _build_index(self) -> None:
        """Build lookup index for fast access."""
        self._stats_index = defaultdict(list)
        for stat in self.stats:
            self._stats_index[(stat.src_ip, stat.service)].append(stat)

    def get_baseline_for_host(
        self,
        src_ip: str,
        service: str | None = None,
    ) -> list[BaselineStats]:
        """Get baseline statistics for a specific host.

        Args:
            src_ip: Source IP (pseudonymized hash).
            service: Optional service filter.

        Returns:
            List of BaselineStats for the host.
        """
        if not self._stats_index:
            self._build_index()

        results: list[BaselineStats] = []
        if service:
            results = self._stats_index.get((src_ip, service), [])
        else:
            for (ip, svc), stats in self._stats_index.items():
                if ip == src_ip:
                    results.extend(stats)
        return results

    def compare_to_baseline(
        self,
        event: ZeekConn,
        baseline: list[BaselineStats] | None = None,
    ) -> dict[str, Any]:
        """Compare a single event against the baseline.

        Computes z-scores and ratio vs p99 for each metric.

        Args:
            event: A ZeekConn event to compare.
            baseline: Optional pre-filtered baseline stats. If None, uses
                the host's baseline.

        Returns:
            Dict with per-metric deviations:
                {metric: {value, z_score, ratio_vs_p99, is_anomaly}}
        """
        if baseline is None:
            service = event.service or "unknown"
            baseline = self.get_baseline_for_host(event.src_ip, service)

        # Build lookup: metric → BaselineStats
        stat_lookup: dict[str, BaselineStats] = {}
        for stat in baseline:
            stat_lookup[stat.metric] = stat

        # Event values
        event_values = {
            "bytes_out": float(event.orig_bytes),
            "bytes_in": float(event.resp_bytes),
            "duration": float(event.duration),
            "pkts_total": float(event.pkts_total),
        }

        result: dict[str, Any] = {}
        for metric, value in event_values.items():
            stat = stat_lookup.get(metric)
            if stat is None or stat.std == 0:
                result[metric] = {
                    "value": value,
                    "z_score": 0.0,
                    "ratio_vs_p99": value / stat.p99 if stat and stat.p99 > 0 else 0.0,
                    "is_anomaly": False,
                }
            else:
                z_score = (value - stat.mean) / stat.std
                ratio_vs_p99 = value / stat.p99 if stat.p99 > 0 else 0.0
                is_anomaly = abs(z_score) > 3.0 or ratio_vs_p99 > 1.0
                result[metric] = {
                    "value": value,
                    "z_score": float(z_score),
                    "ratio_vs_p99": float(ratio_vs_p99),
                    "is_anomaly": is_anomaly,
                }

        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialize the baseline calculator to a dictionary.

        Returns:
            Dict with window_hours and stats list.
        """
        return {
            "window_hours": self.window_hours,
            "stats": [s.model_dump(mode="json") for s in self.stats],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineCalculator:
        """Deserialize a baseline calculator from a dictionary.

        Args:
            data: Dict from to_dict().

        Returns:
            BaselineCalculator instance.
        """
        calc = cls(window_hours=data.get("window_hours", 24))
        calc.stats = [BaselineStats(**s) for s in data.get("stats", [])]
        calc._build_index()
        return calc
