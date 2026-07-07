"""KhaiNet Demo — Backend FastAPI.

Demo web del pipeline de detección + auto-etiquetado de KhaiNet.
Genera tráfico sintético, lo procesa por los 3 modelos (IF, AE, HMM),
ejecuta el sistema de auto-etiquetado multi-fuente con weak supervision
y active learning, y lo muestra en un dashboard en tiempo real.

Uso:
    cd /workspace/demo
    python server.py
    # → http://localhost:4200
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from collections import defaultdict
from contextlib import asynccontextmanager

import numpy as np

# --- Path setup: detection and tuning both use `src` as package name ---
# We load them sequentially: import detection, cache refs, purge sys.modules,
# then import tuning. Finally, restore detection's src for runtime imports.
WORKSPACE = Path(__file__).resolve().parent.parent

# --- FastAPI (no conflict with src) ---
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# ===========================================================================
# Phase 1: Load detection module
# ===========================================================================
sys.path.insert(0, str(WORKSPACE / "detection"))

from src.orchestrator import DetectionOrchestrator
from src.synthetic_data import (
    generate_zeek_conn_logs,
    generate_zeek_dns_logs,
    generate_zeek_http_logs,
    generate_zeek_ssl_logs,
)
from src.models import ZeekConn, ZeekDNS, ZeekHTTP, ZeekSSL, ModelResult
from src.feature_engineering import normalize_features as _detect_normalize

# Purge src.* so tuning can load cleanly
_mods_to_purge = [k for k in sys.modules if k == "src" or k.startswith("src.")]
for k in _mods_to_purge:
    del sys.modules[k]
sys.path.remove(str(WORKSPACE / "detection"))

# ===========================================================================
# Phase 2: Load tuning module
# ===========================================================================
sys.path.insert(0, str(WORKSPACE / "tuning"))

from src.models import (
    ModelScore as TuningModelScore,
    SuricataAlert,
    WazuhAlert,
    MISPEvent,
    BrainCorrelation,
    AnalystFeedback,
    WeakLabel,
    ConsensusLabel,
)
from src.label_sources.suricata_labeler import SuricataLabeler
from src.label_sources.wazuh_labeler import WazuhLabeler
from src.label_sources.misp_labeler import MISPLabeler
from src.label_sources.brain_labeler import BrainLabeler
from src.label_sources.analyst_labeler import AnalystLabeler
from src.weak_supervisor import WeakSupervisor
from src.active_learning import ActiveLearningSelector

# ===========================================================================
# Phase 3: Restore detection's src for orchestrator runtime imports
# The orchestrator's detect() does `from src.feature_engineering import ...`
# at runtime, so we need detection's src active. Tuning classes are already
# loaded in memory, so they don't need tuning's src in the path anymore.
# ===========================================================================
_mods_to_purge2 = [k for k in sys.modules if k == "src" or k.startswith("src.")]
for k in _mods_to_purge2:
    del sys.modules[k]
sys.path.remove(str(WORKSPACE / "tuning"))
sys.path.insert(0, str(WORKSPACE / "detection"))

# Re-import detection src for runtime (orchestrator's internal imports)
from src.orchestrator import DetectionOrchestrator  # noqa: F811
from src.feature_engineering import normalize_features  # noqa: F811

# Suppress noisy logs
import logging

logging.getLogger("structlog").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


# ===========================================================================
# KafkaBridge — replicates demo events to Kafka in parallel
# ===========================================================================


class KafkaBridge:
    """Bridge que envía eventos del demo a Kafka en paralelo.

    El DemoEngine sigue procesando en memoria (rápido),
    pero KafkaBridge replica los mismos eventos a Kafka topics
    para que el pipeline real (detection_consumer, tuning_consumer)
    los procese en paralelo.
    """

    def __init__(self):
        self.enabled = False
        self.producer = None
        self.kafka_admin = None
        self.events_sent = 0
        self.topics_status: dict[str, Any] = {}
        self.consumer_lag: dict[str, Any] = {}
        self._last_check = 0.0

    def try_connect(self) -> bool:
        """Intenta conectar a Kafka. Returns True si éxito."""
        try:
            from kafka import KafkaProducer
            from kafka.admin import KafkaAdminClient

            self.producer = KafkaProducer(
                bootstrap_servers="172.26.10.98:9092",
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                request_timeout_ms=5000,
            )
            self.kafka_admin = KafkaAdminClient(
                bootstrap_servers="172.26.10.98:9092",
                request_timeout_ms=5000,
            )
            self.enabled = True
            print("[KafkaBridge] Connected to 172.26.10.98:9092")
            return True
        except Exception as e:
            print(f"[KafkaBridge] Connection failed: {e}")
            self.enabled = False
            return False

    def send_event(self, topic: str, event: dict):
        """Envía un evento a un topic de Kafka."""
        if not self.enabled or not self.producer:
            return
        try:
            self.producer.send(topic, event)
            self.events_sent += 1
        except Exception:
            pass  # Silent fail - no romper el demo

    def get_status(self) -> dict[str, Any]:
        """Estado de Kafka para el dashboard."""
        if not self.enabled:
            return {
                "connected": False,
                "broker": "172.26.10.98:9092",
                "events_sent": 0,
                "topics": {},
            }

        # Actualizar topics status cada 5 segundos
        now = time.time()
        if now - self._last_check > 5:
            self._last_check = now
            try:
                from kafka import KafkaConsumer

                consumer = KafkaConsumer(
                    bootstrap_servers="172.26.10.98:9092", request_timeout_ms=5000
                )
                topics = list(consumer.topics())
                consumer.close()

                self.topics_status = {}
                for t in sorted(topics):
                    self.topics_status[t] = {"exists": True}
            except Exception:
                pass

        return {
            "connected": True,
            "broker": "172.26.10.98:9092",
            "events_sent": self.events_sent,
            "topics": self.topics_status,
        }

    def close(self):
        """Cierra la conexión con Kafka gracefully."""
        if self.producer:
            try:
                self.producer.flush(timeout=5)
                self.producer.close()
            except Exception:
                pass
        self.enabled = False


# ===========================================================================
# Demo Engine — orchestrates the full pipeline
# ===========================================================================


class DemoEngine:
    """Runs the KhaiNet pipeline in a continuous loop for the demo.

    Lifecycle:
    1. __init__: generate training data, train models
    2. start(): launch background task that generates events every N seconds
    3. Each tick: generate events → detect → label sources → weak supervisor → active learning
    4. WebSocket subscribers receive updates in real time
    """

    def __init__(self):
        self.orchestrator: DetectionOrchestrator | None = None
        self.is_trained = False

        # Label sources
        self.sources: list[Any] = []
        self.supervisor: WeakSupervisor | None = None
        self.al_selector: ActiveLearningSelector | None = None

        # State
        self.tick_count = 0
        self.total_events = 0
        self.total_anomalies = 0
        self.total_labeled = 0
        self.total_analyst_reviews = 0
        self.recent_events: list[dict] = []
        self.recent_labels: list[dict] = []
        self.active_learning_queue: list[dict] = []
        self.reviewed_event_ids: set[str] = set()
        self.analyst_feedbacks: list[AnalystFeedback] = []
        self.source_stats: dict[str, dict] = {}
        self.model_thresholds: dict[str, float] = {
            "isolation_forest": 0.7,
            "autoencoder": 0.7,
            "hmm": 0.7,
        }

        # WebSocket subscribers
        self.subscribers: list[WebSocket] = []

        # Background task
        self._task: asyncio.Task | None = None
        self._running = False

        # IP pool for generating consistent events
        self._rng = random.Random(42)
        self._salt = "khainet-salt"
        self._tick_seed = 100

        # Kafka bridge (parallel event replication)
        self.kafka = KafkaBridge()

        # Device IP pool from network topology (for mapping events to real devices)
        self._device_ips: list[dict] = []  # populated in initialize()
        self._ip_to_device: dict[str, str] = {}  # ip → device_id
        self._active_links: list[dict] = []  # active links for network map

    def _pseudonymize(self, seed: str) -> str:
        return hashlib.sha256(f"{self._salt}:{seed}".encode()).hexdigest()[:16]

    def _random_ip(self, prefix: str = "host") -> str:
        return self._pseudonymize(f"{prefix}-{self._rng.randint(0, 100000)}")

    def initialize(self):
        """Train models on synthetic data at startup."""
        print("[Demo] Generating training data...")
        conn = generate_zeek_conn_logs(n_events=3000, anomaly_ratio=0.05, seed=42)
        dns = generate_zeek_dns_logs(n_events=1000, anomaly_ratio=0.05, seed=43)
        http = generate_zeek_http_logs(n_events=500, anomaly_ratio=0.05, seed=44)
        ssl = generate_zeek_ssl_logs(n_events=300, anomaly_ratio=0.05, seed=45)

        print(f"[Demo] Training models on {len(conn)} conn events...")
        config = {
            "isolation_forest": {
                "n_estimators": 50,
                "contamination": 0.05,
                "random_state": 42,
                "threshold": 0.7,
            },
            "autoencoder": {
                "hidden_dims": [32, 16, 8],
                "epochs": 20,
                "batch_size": 64,
                "learning_rate": 1e-3,
                "threshold_percentile": 99,
                "random_state": 42,
            },
            "hmm": {
                "n_components": 4,
                "n_iter": 50,
                "random_state": 42,
                "covariance_type": "diag",
            },
            "baseline": {"window_hours": 24},
            "feature_engineering": {"window_minutes": 5},
        }
        self.orchestrator = DetectionOrchestrator(config)
        summary = self.orchestrator.train_all(conn, dns, http, ssl)
        self.is_trained = True
        print(
            f"[Demo] Models trained: IF={summary['if_trained']}, AE={summary['ae_trained']}, HMM={summary['hmm_trained']}"
        )

        # Initialize label sources
        self.sources = [
            SuricataLabeler(weight=1.2, min_confidence=0.5),
            WazuhLabeler(weight=1.0, min_confidence=0.3),
            MISPLabeler(weight=1.3, min_confidence=0.5),
            BrainLabeler(weight=0.7, min_confidence=0.3),
            AnalystLabeler(weight=2.0, min_confidence=0.0),
        ]
        self.supervisor = WeakSupervisor(
            sources=self.sources,
            decision_threshold=0.0,
            abstain_threshold=0.0,
            analyst_override=True,
        )
        self.al_selector = ActiveLearningSelector(
            strategy="hybrid",
            batch_size=10,
        )
        print(
            "[Demo] Auto-labeling system initialized (5 sources, weak supervisor, active learning)"
        )

        # Try connecting to Kafka (non-blocking, graceful fallback)
        self.kafka.try_connect()

        # Build device IP pool from network topology for event generation
        self._device_ips = [
            {"id": d["id"], "ip": d["ip"], "zone": d["zone"], "name": d["name"]}
            for d in NETWORK_TOPOLOGY["devices"]
        ]
        self._ip_to_device = {d["ip"]: d["id"] for d in self._device_ips}
        print(f"[Demo] Device IP pool: {len(self._device_ips)} devices from topology")

    def _generate_tick_events(
        self,
    ) -> tuple[
        list[ZeekConn], list[ZeekDNS], list[ZeekHTTP], list[ZeekSSL], dict[str, bool]
    ]:
        """Generate a small batch of events for one tick.

        Returns (conn, dns, http, ssl, ground_truth_map) where ground_truth_map
        maps uid → is_anomaly (based on which generator pattern was used).
        """
        self._tick_seed += 1
        rng = random.Random(self._tick_seed)
        n_events = rng.randint(8, 20)
        n_anomalies = max(1, int(n_events * rng.uniform(0.1, 0.3)))

        now = datetime.now(timezone.utc)
        conn_events: list[ZeekConn] = []
        ground_truth: dict[str, bool] = {}

        # Use real device IPs from the network topology
        device_pool = self._device_ips if self._device_ips else []
        if device_pool:
            src_devices = rng.sample(device_pool, min(5, len(device_pool)))
            dst_devices = rng.sample(device_pool, min(10, len(device_pool)))
            src_hosts = [d["ip"] for d in src_devices]
            dst_hosts = [d["ip"] for d in dst_devices]
        else:
            src_hosts = [
                self._random_ip(f"tick-src-{self._tick_seed}-{i}") for i in range(5)
            ]
            dst_hosts = [
                self._random_ip(f"tick-dst-{self._tick_seed}-{i}") for i in range(10)
            ]

        anomaly_types = ["scan", "exfiltration", "c2_beaconing", "lateral_movement"]

        for i in range(n_events):
            is_anomaly = i < n_anomalies
            uid = f"tick-{self._tick_seed}-{i}"
            ts = now + timedelta(seconds=i)

            if is_anomaly:
                atype = rng.choice(anomaly_types)
                src = rng.choice(src_hosts)
                if atype == "scan":
                    evt = ZeekConn(
                        timestamp=ts,
                        uid=uid,
                        src_ip=src,
                        dst_ip=self._random_ip(f"scan-{i}"),
                        src_port=rng.randint(1024, 65535),
                        dst_port=rng.choice([22, 445, 3389]),
                        protocol="tcp",
                        duration=round(rng.uniform(0.001, 0.05), 6),
                        orig_bytes=rng.randint(0, 100),
                        resp_bytes=0,
                        orig_pkts=1,
                        resp_pkts=0,
                        service=None,
                        conn_state="S0",
                    )
                elif atype == "exfiltration":
                    evt = ZeekConn(
                        timestamp=ts,
                        uid=uid,
                        src_ip=src,
                        dst_ip=rng.choice(dst_hosts),
                        src_port=rng.randint(1024, 65535),
                        dst_port=443,
                        protocol="tcp",
                        duration=round(rng.uniform(10, 120), 6),
                        orig_bytes=rng.randint(5_000_000, 20_000_000),
                        resp_bytes=rng.randint(100, 500),
                        orig_pkts=rng.randint(1000, 10000),
                        resp_pkts=rng.randint(10, 50),
                        service="ssl",
                        conn_state="SF",
                    )
                elif atype == "c2_beaconing":
                    evt = ZeekConn(
                        timestamp=ts,
                        uid=uid,
                        src_ip=src,
                        dst_ip=self._random_ip(f"c2-{i}"),
                        src_port=rng.randint(1024, 65535),
                        dst_port=rng.choice([443, 8080]),
                        protocol="tcp",
                        duration=round(rng.uniform(0.01, 0.3), 6),
                        orig_bytes=rng.randint(50, 200),
                        resp_bytes=rng.randint(50, 200),
                        orig_pkts=2,
                        resp_pkts=2,
                        service="ssl",
                        conn_state="SF",
                    )
                else:  # lateral_movement
                    evt = ZeekConn(
                        timestamp=ts,
                        uid=uid,
                        src_ip=src,
                        dst_ip=self._random_ip(f"lat-{i}"),
                        src_port=rng.randint(1024, 65535),
                        dst_port=rng.choice([135, 139, 445, 3389, 5985]),
                        protocol="tcp",
                        duration=round(rng.uniform(0.1, 3.0), 6),
                        orig_bytes=rng.randint(1000, 20000),
                        resp_bytes=rng.randint(1000, 20000),
                        orig_pkts=rng.randint(10, 50),
                        resp_pkts=rng.randint(10, 50),
                        service=None,
                        conn_state="SF",
                    )
                ground_truth[uid] = True
            else:
                evt = ZeekConn(
                    timestamp=ts,
                    uid=uid,
                    src_ip=rng.choice(src_hosts),
                    dst_ip=rng.choice(dst_hosts),
                    src_port=rng.randint(1024, 65535),
                    dst_port=rng.choice([80, 443, 22, 53, 25]),
                    protocol="tcp",
                    duration=round(rng.uniform(0.01, 5.0), 6),
                    orig_bytes=rng.randint(100, 30000),
                    resp_bytes=rng.randint(500, 100000),
                    orig_pkts=rng.randint(1, 30),
                    resp_pkts=rng.randint(1, 30),
                    service=rng.choice(["http", "ssl", "ssh", "dns"]),
                    conn_state="SF",
                )
                ground_truth[uid] = False

            conn_events.append(evt)

        # Generate a few DNS events
        dns_events: list[ZeekDNS] = []
        for i in range(rng.randint(2, 5)):
            uid = f"dns-{self._tick_seed}-{i}"
            ts = now + timedelta(seconds=i)
            dns_events.append(
                ZeekDNS(
                    timestamp=ts,
                    uid=uid,
                    src_ip=rng.choice(src_hosts),
                    dst_ip=self._random_ip("dns-srv"),
                    src_port=rng.randint(1024, 65535),
                    dst_port=53,
                    protocol="udp",
                    query=rng.choice(
                        ["google.com", "example.com", "internal.corp.local"]
                    ),
                    qclass=1,
                    qtype="A",
                    rcode="NOERROR",
                    rcode_name="NOERROR",
                    answers=["10.0.0.1"],
                    ttl=[300],
                )
            )

        return conn_events, dns_events, [], [], ground_truth

    def _generate_source_alerts(
        self, conn_events: list[ZeekConn], ground_truth: dict[str, bool]
    ) -> dict[str, Any]:
        """Generate synthetic alerts from label sources matching the tick's events.

        Each source detects a subset of anomalies (with some noise).
        """
        rng = random.Random(self._tick_seed + 999)
        anomaly_events = [e for e in conn_events if ground_truth.get(e.uid, False)]
        normal_events = [e for e in conn_events if not ground_truth.get(e.uid, False)]

        source_data: dict[str, Any] = {}

        # Suricata: detects ~60% of anomalies, few false positives
        suricata_alerts: list[SuricataAlert] = []
        for evt in anomaly_events:
            if rng.random() < 0.6:
                suricata_alerts.append(
                    SuricataAlert(
                        timestamp=evt.timestamp,
                        src_ip=evt.src_ip,
                        dst_ip=evt.dst_ip,
                        src_port=evt.src_port,
                        dst_port=evt.dst_port,
                        protocol=evt.protocol,
                        alert_signature=f"ET ALERT - suspicious traffic",
                        alert_category=rng.choice(
                            [
                                "Trojan Activity",
                                "Network Scan",
                                "Data Exfiltration",
                                "DNS Tunneling",
                            ]
                        ),
                        alert_severity=rng.choice([1, 2, 2, 3]),
                        rule_id=f"sid:{rng.randint(2000000, 2100000)}",
                        mitre_attack_id=rng.choice(["T1041", "T1595", "T1021", None]),
                    )
                )
        # Small false positive rate
        for evt in normal_events[:1]:
            if rng.random() < 0.1:
                suricata_alerts.append(
                    SuricataAlert(
                        timestamp=evt.timestamp,
                        src_ip=evt.src_ip,
                        dst_ip=evt.dst_ip,
                        src_port=evt.src_port,
                        dst_port=evt.dst_port,
                        protocol=evt.protocol,
                        alert_signature="ET POLICY unusual port",
                        alert_category="Policy Violation",
                        alert_severity=3,
                        rule_id=f"sid:{rng.randint(2000000, 2100000)}",
                    )
                )
        source_data["suricata"] = suricata_alerts

        # Wazuh: detects ~40% of anomalies
        wazuh_alerts: list[WazuhAlert] = []
        for evt in anomaly_events:
            if rng.random() < 0.4:
                wazuh_alerts.append(
                    WazuhAlert(
                        timestamp=evt.timestamp,
                        src_ip=evt.src_ip,
                        dst_ip=evt.dst_ip,
                        agent_id=str(rng.randint(1, 20)),
                        agent_name=f"agent-{rng.randint(1, 20)}",
                        rule_id=f"rule-{rng.randint(500000, 510000)}",
                        rule_level=rng.choice([7, 9, 12]),
                        rule_description=f"Suspicious activity detected",
                        rule_groups=[rng.choice(["syscheck", "rootcheck", "auth"])],
                        event_type="security",
                    )
                )
        source_data["wazuh"] = wazuh_alerts

        # MISP: detects ~30% of anomalies
        misp_events: list[MISPEvent] = []
        for evt in anomaly_events:
            if rng.random() < 0.3:
                misp_events.append(
                    MISPEvent(
                        timestamp=evt.timestamp,
                        src_ip=evt.dst_ip,
                        dst_ip=evt.dst_ip,
                        ioc_type="ip-dst",
                        ioc_value=evt.dst_ip,
                        event_id=f"misp-{rng.randint(1, 1000)}",
                        event_info="Known malicious infrastructure",
                        threat_level=rng.choice([1, 2]),
                        tags=[rng.choice(["malware", "c2", "apt"])],
                        mitre_attack_id=rng.choice(["T1041", "T1595", None]),
                    )
                )
        source_data["misp"] = misp_events

        # Brain: detects ~50% of anomalies (correlates patterns)
        brain_corrs: list[BrainCorrelation] = []
        for evt in anomaly_events:
            if rng.random() < 0.5:
                brain_corrs.append(
                    BrainCorrelation(
                        timestamp=evt.timestamp,
                        src_ip=evt.src_ip,
                        dst_ip=evt.dst_ip,
                        mitre_tactic=rng.choice(
                            [
                                "Exfiltration",
                                "Command and Control",
                                "Lateral Movement",
                                "Discovery",
                            ]
                        ),
                        mitre_technique="T1041 - Exfiltration Over C2 Channel",
                        mitre_attack_id=rng.choice(["T1041", "T1595", "T1021"]),
                        contributing_events=[evt.uid],
                        confidence=rng.uniform(0.5, 0.85),
                        narrative=f"Brain detected suspicious pattern from {evt.src_ip[:8]}...",
                        models_involved=rng.sample(
                            ["isolation_forest", "autoencoder", "hmm"], k=2
                        ),
                    )
                )
        source_data["brain"] = brain_corrs

        # Analyst: use accumulated feedback
        source_data["analyst"] = list(self.analyst_feedbacks)

        return source_data

    def _detection_to_tuning_scores(
        self, results: list[ModelResult]
    ) -> list[TuningModelScore]:
        """Convert detection ModelResults to tuning ModelScores."""
        scores = []
        # Group by event (same event_id across models)
        # In detection, each model produces results per event. We need to map
        # them to a common event_id. The orchestrator produces results per
        # model per event, but event_ids are per-model. We'll use the
        # timestamp + src_ip as a composite key.
        for r in results:
            scores.append(
                TuningModelScore(
                    event_id=r.event_id,
                    timestamp=r.timestamp,
                    src_ip=r.src_ip,
                    dst_ip=r.details.get("dst_ip", ""),
                    model_name=r.model_name,
                    score=r.score,
                    features={"is_anomaly": r.is_anomaly, "threshold": r.threshold},
                )
            )
        return scores

    async def _tick(self):
        """Run one cycle of the pipeline."""
        self.tick_count += 1

        # 1. Generate events
        conn, dns, http, ssl, ground_truth = self._generate_tick_events()

        # 1b. Send to Kafka if connected (parallel replication)
        if self.kafka.enabled:
            for evt in conn:
                self.kafka.send_event("zeek-conn", evt.model_dump())
            for evt in dns:
                self.kafka.send_event("zeek-dns", evt.model_dump())
            for evt in http:
                self.kafka.send_event("zeek-http", evt.model_dump())
            for evt in ssl:
                self.kafka.send_event("zeek-ssl", evt.model_dump())

        # 2. Detect anomalies
        results = self.orchestrator.detect(conn, dns, http, ssl)

        # 3. Convert to tuning scores
        tuning_scores = self._detection_to_tuning_scores(results)

        # 4. Generate source alerts
        source_data = self._generate_source_alerts(conn, ground_truth)

        # 5. Run weak supervisor
        consensus_labels = self.supervisor.label_events(
            events=tuning_scores,
            source_data=source_data,
            window_seconds=60.0,
        )

        # 6. Get unlabeled events for active learning
        unlabeled = self.supervisor.get_unlabeled_events(
            tuning_scores, consensus_labels
        )

        # 7. Active learning batch (from all events, not just unlabeled)
        al_batch = self.al_selector.select_batch(
            events=tuning_scores,
            thresholds=self.model_thresholds,
            exclude_event_ids=self.reviewed_event_ids,
        )

        # 8. Update stats
        n_anomalies = sum(1 for v in ground_truth.values() if v)
        self.total_events += len(conn)
        self.total_anomalies += n_anomalies
        self.total_labeled += len(consensus_labels)

        # Update source stats
        all_weak_labels = []
        for source in self.sources:
            raw = source_data.get(source.name)
            if raw is None:
                continue
            labels = source.generate_labels(raw)
            matched = source.match_to_events(labels, tuning_scores, 60.0)
            all_weak_labels.extend(matched)
        self.source_stats = self.supervisor.get_source_statistics(all_weak_labels)

        # 9. Build event records for the frontend
        # Group model results by event (using timestamp + src_ip as key)
        events_by_key: dict[str, list[ModelResult]] = defaultdict(list)
        for r in results:
            key = f"{r.timestamp.isoformat()}|{r.src_ip}"
            events_by_key[key].append(r)

        event_records = []
        for key, model_results in events_by_key.items():
            first = model_results[0]
            scores = {r.model_name: round(r.score, 4) for r in model_results}
            avg_score = round(float(np.mean([r.score for r in model_results])), 4)
            is_anomaly = any(r.is_anomaly for r in model_results)

            # Find matching consensus label
            consensus = None
            for cl in consensus_labels:
                if (
                    cl.src_ip == first.src_ip
                    and abs(cl.ts_epoch - first.timestamp.timestamp()) < 60
                ):
                    consensus = cl
                    break

            # Find ground truth
            gt = None
            for e in conn:
                if (
                    e.src_ip == first.src_ip
                    and abs(e.timestamp.timestamp() - first.timestamp.timestamp()) < 1
                ):
                    gt = ground_truth.get(e.uid)
                    break

            event_records.append(
                {
                    "id": key,
                    "timestamp": first.timestamp.isoformat(),
                    "src_ip": first.src_ip[:12] + "...",
                    "scores": scores,
                    "avg_score": avg_score,
                    "is_anomaly": is_anomaly,
                    "ground_truth": gt,
                    "consensus_label": {
                        "label": consensus.label,
                        "confidence": round(consensus.confidence, 3),
                        "sources": consensus.contributing_sources,
                        "votes_pos": consensus.votes_positive,
                        "votes_neg": consensus.votes_negative,
                    }
                    if consensus
                    else None,
                }
            )

        # Sort by avg score descending (most suspicious first)
        event_records.sort(key=lambda x: x["avg_score"], reverse=True)
        self.recent_events = event_records[:50]

        # 9b. Extract active links for the network map
        # Events with high score → animate the corresponding link in the SVG
        # Map src_ip/dst_ip to device IDs using the topology
        active_links = []
        score_threshold = 0.65
        seen_pairs = set()
        for evt_record in event_records:
            if evt_record["avg_score"] < score_threshold:
                continue
            # Find the original conn event to get dst_ip
            src_ip_full = None
            dst_ip_full = None
            for e in conn:
                if e.src_ip == evt_record["src_ip"].rstrip(".") or e.src_ip.startswith(
                    evt_record["src_ip"].rstrip(".")
                ):
                    src_ip_full = e.src_ip
                    dst_ip_full = e.dst_ip
                    break
            if not src_ip_full:
                # Try matching by timestamp
                for e in conn:
                    if (
                        abs(
                            e.timestamp.timestamp()
                            - datetime.fromisoformat(
                                evt_record["timestamp"]
                            ).timestamp()
                        )
                        < 1
                    ):
                        src_ip_full = e.src_ip
                        dst_ip_full = e.dst_ip
                        break
            if not src_ip_full or not dst_ip_full:
                continue
            src_dev = self._ip_to_device.get(src_ip_full)
            dst_dev = self._ip_to_device.get(dst_ip_full)
            if not src_dev or not dst_dev:
                continue
            pair = f"{src_dev}->{dst_dev}"
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            active_links.append(
                {
                    "from": src_dev,
                    "to": dst_dev,
                    "score": evt_record["avg_score"],
                    "is_anomaly": evt_record["is_anomaly"],
                    "timestamp": evt_record["timestamp"],
                }
            )
        self._active_links = active_links[:20]  # Keep last 20 active links

        # 10. Build label records
        label_records = []
        for cl in consensus_labels:
            label_records.append(
                {
                    "event_id": cl.event_id[:8],
                    "timestamp": cl.timestamp.isoformat(),
                    "src_ip": cl.src_ip[:12] + "...",
                    "label": cl.label,
                    "confidence": round(cl.confidence, 3),
                    "sources": cl.contributing_sources,
                    "votes_pos": cl.votes_positive,
                    "votes_neg": cl.votes_negative,
                    "mitre": cl.mitre_attack_id,
                }
            )
        self.recent_labels = label_records[:30]

        # 11. Build active learning queue
        al_records = []
        for q in al_batch.queries:
            al_records.append(
                {
                    "query_id": q.query_id[:8],
                    "event_id": q.event_id[:8],
                    "timestamp": q.timestamp.isoformat(),
                    "src_ip": q.src_ip[:12] + "...",
                    "model_scores": {k: round(v, 4) for k, v in q.model_scores.items()},
                    "unified_score": round(q.unified_score, 4),
                    "threshold": round(q.current_threshold, 3),
                    "reason": q.selection_reason,
                    "uncertainty": round(q.uncertainty_score, 4),
                    "suggested": q.suggested_label,
                }
            )
        self.active_learning_queue = al_records

        # 12. Broadcast to WebSocket subscribers
        await self._broadcast(
            {
                "type": "tick",
                "tick": self.tick_count,
                "events": self.recent_events[:15],
                "labels": self.recent_labels[:10],
                "active_learning": self.active_learning_queue[:5],
                "stats": self.get_stats(),
                "source_stats": self._serialize_source_stats(),
                "active_links": self._active_links,
            }
        )

    def _serialize_source_stats(self) -> dict[str, Any]:
        """Convert source stats to JSON-serializable format."""
        result = {}
        for name, stats in self.source_stats.items():
            result[name] = {
                "count": stats["count"],
                "positive": stats["positive"],
                "negative": stats["negative"],
                "abstain": stats["abstain"],
                "avg_confidence": round(stats["avg_confidence"], 3),
            }
        return result

    def get_stats(self) -> dict[str, Any]:
        return {
            "tick": self.tick_count,
            "total_events": self.total_events,
            "total_anomalies": self.total_anomalies,
            "total_labeled": self.total_labeled,
            "total_unlabeled": self.total_events - self.total_labeled,
            "analyst_reviews": self.total_analyst_reviews,
            "is_trained": self.is_trained,
            "models": {
                "isolation_forest": self.orchestrator.if_detector.model is not None
                if self.orchestrator
                else False,
                "autoencoder": self.orchestrator.ae_detector.model is not None
                if self.orchestrator
                else False,
                "hmm": self.orchestrator.hmm_detector.model is not None
                if self.orchestrator
                else False,
            },
            "thresholds": self.model_thresholds,
            "kafka": self.kafka.get_status(),
        }

    async def _broadcast(self, message: dict):
        """Send a message to all WebSocket subscribers."""
        dead = []
        for ws in self.subscribers:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.subscribers.remove(ws)

    async def start(self):
        """Start the background loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop())
        print("[Demo] Background loop started")

    async def stop(self):
        """Stop the background loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("[Demo] Background loop stopped")

    async def _loop(self):
        """Main loop: run a tick every 5 seconds."""
        # Initial tick
        await self._tick()
        while self._running:
            await asyncio.sleep(5)
            if self._running:
                await self._tick()

    def add_analyst_feedback(self, event_id: str, label: bool, notes: str = "") -> dict:
        """Process analyst feedback from the active learning panel."""
        # Find the event in recent events
        # Create AnalystFeedback
        now = datetime.now(timezone.utc)
        feedback = AnalystFeedback(
            timestamp=now,
            src_ip="analyst-review",
            dst_ip="analyst-review",
            label=label,
            analyst_id="demo-analyst",
            event_id=event_id,
            notes=notes,
        )
        self.analyst_feedbacks.append(feedback)
        self.reviewed_event_ids.add(event_id)
        self.total_analyst_reviews += 1
        print(f"[Demo] Analyst feedback: event={event_id[:8]}, label={label}")

        return {
            "status": "ok",
            "event_id": event_id,
            "label": label,
            "total_reviews": self.total_analyst_reviews,
        }


# ===========================================================================
# FastAPI app
# ===========================================================================

engine = DemoEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    engine.initialize()
    await engine.start()
    yield
    # Shutdown
    await engine.stop()
    engine.kafka.close()


app = FastAPI(title="KhaiNet Demo", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main dashboard HTML."""
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(html_path.read_text())


@app.get("/api/stats")
async def get_stats():
    return JSONResponse(engine.get_stats())


@app.get("/api/events")
async def get_events():
    return JSONResponse(
        {
            "events": engine.recent_events,
            "labels": engine.recent_labels,
            "active_learning": engine.active_learning_queue,
            "source_stats": engine._serialize_source_stats(),
        }
    )


@app.post("/api/analyst-feedback")
async def analyst_feedback(body: dict):
    """Process analyst feedback from the active learning panel."""
    event_id = body.get("event_id", "")
    label = body.get("label", True)
    notes = body.get("notes", "")
    result = engine.add_analyst_feedback(event_id, label, notes)
    return JSONResponse(result)


@app.get("/api/kafka/status")
async def kafka_status():
    """Estado de la conexión Kafka."""
    return JSONResponse(engine.kafka.get_status())


@app.get("/api/kafka/topics")
async def kafka_topics():
    """Lista de topics de Kafka disponibles."""
    status = engine.kafka.get_status()
    return JSONResponse(
        {
            "topics": status.get("topics", {}),
            "connected": status.get("connected", False),
        }
    )


# ===========================================================================
# Network topology & device inventory (mock data for design phase)
# ===========================================================================

# --- Mock network topology ---
# Represents a typical enterprise network with zones, devices, and connections.
# When real sensors are deployed, this will be populated from Zeek + asset inventory.

NETWORK_TOPOLOGY = {
    "zones": [
        {
            "id": "internet",
            "name": "Internet",
            "type": "external",
            "color": "#ef4444",
            "desc": "Tráfico externo — todo lo que entra/sale de la red corporativa",
        },
        {
            "id": "dmz",
            "name": "DMZ",
            "type": "dmz",
            "color": "#f59e0b",
            "desc": "Servidores expuestos al exterior: web, mail, VPN",
        },
        {
            "id": "core",
            "name": "Core",
            "type": "internal",
            "color": "#3b82f6",
            "desc": "Servidores internos: AD, DNS, file servers, bases de datos",
        },
        {
            "id": "lan",
            "name": "LAN",
            "type": "internal",
            "color": "#10b981",
            "desc": "Estaciones de trabajo y dispositivos de usuarios",
        },
        {
            "id": "iot",
            "name": "IoT/OT",
            "type": "iot",
            "color": "#8b5cf6",
            "desc": "Dispositivos IoT, cámaras, impresoras, SCADA",
        },
    ],
    "devices": [
        # Internet
        {
            "id": "ext-c2",
            "name": "C2 Server (malicioso)",
            "ip": "203.0.113.45",
            "zone": "internet",
            "type": "external",
            "os": "unknown",
            "risk": "critical",
            "tags": ["c2", "malicious"],
            "first_seen": "2025-01-15",
            "notes": "Servidor C2 conocido — beaconing detectado",
        },
        # DMZ
        {
            "id": "fw-01",
            "name": "Firewall Perimetral",
            "ip": "10.0.0.1",
            "zone": "dmz",
            "type": "firewall",
            "os": "pfSense",
            "risk": "low",
            "tags": ["perimeter", "critical-infra"],
            "first_seen": "2024-06-01",
            "notes": "Firewall principal — todo el tráfico pasa por aquí",
        },
        {
            "id": "web-01",
            "name": "Web Server",
            "ip": "10.0.0.10",
            "zone": "dmz",
            "type": "server",
            "os": "Ubuntu 22.04",
            "risk": "medium",
            "tags": ["web", "public"],
            "first_seen": "2024-06-01",
            "notes": "Servidor web público — nginx + app",
        },
        {
            "id": "mail-01",
            "name": "Mail Server",
            "ip": "10.0.0.20",
            "zone": "dmz",
            "type": "server",
            "os": "Debian 12",
            "risk": "medium",
            "tags": ["mail", "smtp"],
            "first_seen": "2024-06-01",
            "notes": "Postfix + Dovecot",
        },
        {
            "id": "vpn-01",
            "name": "VPN Gateway",
            "ip": "10.0.0.30",
            "zone": "dmz",
            "type": "gateway",
            "os": "OpenWrt",
            "risk": "low",
            "tags": ["vpn", "remote-access"],
            "first_seen": "2024-06-01",
            "notes": "WireGuard VPN para acceso remoto",
        },
        # Core
        {
            "id": "dc-01",
            "name": "Domain Controller 01",
            "ip": "10.1.0.5",
            "zone": "core",
            "type": "server",
            "os": "Windows Server 2019",
            "risk": "high",
            "tags": ["ad", "critical-infra", "crown-jewel"],
            "first_seen": "2024-06-01",
            "notes": "Active Directory principal — objetivo crítico",
        },
        {
            "id": "dc-02",
            "name": "Domain Controller 02",
            "ip": "10.1.0.6",
            "zone": "core",
            "type": "server",
            "os": "Windows Server 2019",
            "risk": "high",
            "tags": ["ad", "critical-infra", "crown-jewel"],
            "first_seen": "2024-06-01",
            "notes": "Active Directory secundario (redundancia)",
        },
        {
            "id": "fs-01",
            "name": "File Server",
            "ip": "10.1.0.20",
            "zone": "core",
            "type": "server",
            "os": "Windows Server 2019",
            "risk": "medium",
            "tags": ["file-share", "smb"],
            "first_seen": "2024-06-01",
            "notes": "File server con shares departamentales",
        },
        {
            "id": "db-01",
            "name": "Database Server",
            "ip": "10.1.0.50",
            "zone": "core",
            "type": "server",
            "os": "RHEL 9",
            "risk": "high",
            "tags": ["database", "critical-infra"],
            "first_seen": "2024-06-01",
            "notes": "PostgreSQL — datos sensibles de clientes",
        },
        {
            "id": "dns-01",
            "name": "DNS Server",
            "ip": "10.1.0.10",
            "zone": "core",
            "type": "server",
            "os": "Ubuntu 22.04",
            "risk": "low",
            "tags": ["dns", "infra"],
            "first_seen": "2024-06-01",
            "notes": "Bind9 — DNS interno",
        },
        # LAN
        {
            "id": "ws-01",
            "name": "Workstation Finanzas",
            "ip": "10.2.0.100",
            "zone": "lan",
            "type": "workstation",
            "os": "Windows 11",
            "risk": "medium",
            "tags": ["finance", "user"],
            "first_seen": "2024-09-15",
            "notes": "Equipo del departamento de finanzas",
        },
        {
            "id": "ws-02",
            "name": "Workstation RRHH",
            "ip": "10.2.0.101",
            "zone": "lan",
            "type": "workstation",
            "os": "Windows 11",
            "risk": "low",
            "tags": ["hr", "user"],
            "first_seen": "2024-09-15",
            "notes": "Equipo de RRHH",
        },
        {
            "id": "ws-03",
            "name": "Workstation IT",
            "ip": "10.2.0.110",
            "zone": "lan",
            "type": "workstation",
            "os": "Ubuntu 24.04",
            "risk": "medium",
            "tags": ["it", "admin"],
            "first_seen": "2024-06-01",
            "notes": "Equipo de administración IT",
        },
        {
            "id": "ws-04",
            "name": "Workstation Comprometida",
            "ip": "10.2.0.105",
            "zone": "lan",
            "type": "workstation",
            "os": "Windows 11",
            "risk": "critical",
            "tags": ["compromised", "patient-zero"],
            "first_seen": "2024-09-15",
            "notes": "Patient zero — posible punto de entrada de incidente",
        },
        # IoT/OT
        {
            "id": "cam-01",
            "name": "Cámara IP Entrada",
            "ip": "10.3.0.50",
            "zone": "iot",
            "type": "iot",
            "os": "Embedded",
            "risk": "medium",
            "tags": ["camera", "iot"],
            "first_seen": "2024-06-01",
            "notes": "Cámara de seguridad — firmware desactualizado",
        },
        {
            "id": "prn-01",
            "name": "Impresora Red",
            "ip": "10.3.0.60",
            "zone": "iot",
            "type": "iot",
            "os": "Embedded",
            "risk": "low",
            "tags": ["printer", "iot"],
            "first_seen": "2024-06-01",
            "notes": "Impresora multifunción de red",
        },
        {
            "id": "scada-01",
            "name": "PLC Línea 1",
            "ip": "10.3.0.100",
            "zone": "iot",
            "type": "ot",
            "os": "RTOS",
            "risk": "high",
            "tags": ["scada", "ot", "critical-infra"],
            "first_seen": "2024-03-01",
            "notes": "Controlador lógico programable — línea de producción",
        },
    ],
    "links": [
        # Internet ↔ DMZ
        {"from": "ext-c2", "to": "fw-01", "type": "malicious", "label": "C2 beaconing"},
        {"from": "fw-01", "to": "web-01", "type": "normal", "label": "HTTP/S"},
        {"from": "fw-01", "to": "mail-01", "type": "normal", "label": "SMTP"},
        {"from": "fw-01", "to": "vpn-01", "type": "normal", "label": "VPN"},
        # DMZ ↔ Core
        {"from": "web-01", "to": "db-01", "type": "normal", "label": "SQL"},
        {"from": "mail-01", "to": "dc-01", "type": "normal", "label": "LDAP"},
        {"from": "vpn-01", "to": "dc-01", "type": "normal", "label": "Auth"},
        # Core internal
        {"from": "dc-01", "to": "dc-02", "type": "normal", "label": "AD Sync"},
        {"from": "dc-01", "to": "dns-01", "type": "normal", "label": "DNS"},
        {"from": "dc-01", "to": "fs-01", "type": "normal", "label": "SMB"},
        # Core ↔ LAN
        {"from": "dc-01", "to": "ws-01", "type": "normal", "label": "AD Auth"},
        {"from": "dc-01", "to": "ws-02", "type": "normal", "label": "AD Auth"},
        {"from": "dc-01", "to": "ws-03", "type": "normal", "label": "AD Auth"},
        {"from": "dc-01", "to": "ws-04", "type": "normal", "label": "AD Auth"},
        {"from": "fs-01", "to": "ws-01", "type": "normal", "label": "SMB Share"},
        {"from": "fs-01", "to": "ws-02", "type": "normal", "label": "SMB Share"},
        # Incident paths (malicious)
        {
            "from": "ws-04",
            "to": "dc-01",
            "type": "malicious",
            "label": "Lateral movement",
        },
        {"from": "ws-04", "to": "fs-01", "type": "malicious", "label": "Data staging"},
        {"from": "ws-04", "to": "ext-c2", "type": "malicious", "label": "Exfiltration"},
        # IoT
        {"from": "cam-01", "to": "fw-01", "type": "normal", "label": "NTP"},
        {"from": "scada-01", "to": "ws-03", "type": "normal", "label": "Modbus"},
    ],
    "incidents": [
        {
            "id": "INC-001",
            "name": "C2 Beaconing + Exfiltration",
            "status": "active",
            "severity": "critical",
            "patient_zero": "ws-04",
            "path": ["ext-c2", "fw-01", "ws-04", "dc-01", "fs-01", "ws-04", "ext-c2"],
            "description": "Workstation comprometida hace beaconing a C2, luego intenta lateral movement al DC, staging en file server, y exfiltration al exterior.",
            "mitre": ["T1071", "T1021", "T1078", "T1005", "T1041"],
            "detected_by": ["isolation_forest", "autoencoder", "brain"],
            "first_seen": "2025-01-15T08:30:00Z",
        },
        {
            "id": "INC-002",
            "name": "Port Scan desde IoT",
            "status": "contained",
            "severity": "medium",
            "patient_zero": "cam-01",
            "path": ["cam-01", "fw-01", "dc-01"],
            "description": "Cámara IP comprometida escaneando puertos del firewall y DC.",
            "mitre": ["T1595", "T1046"],
            "detected_by": ["isolation_forest", "suricata"],
            "first_seen": "2025-01-10T14:00:00Z",
        },
    ],
}

# --- Mock infrastructure services ---
# --- Stack KhaiNet desplegado en Portainer (ID 24, docker02) ---
# 11 containers reales + servicios planificados (Shuffle, TheHive, MISP)
INFRA_SERVICES = [
    # === Core: Kafka bus ===
    {
        "name": "Kafka",
        "container": "khainet-kafka",
        "component": "Message Bus",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.2",
        "port": 9092,
        "image": "apache/kafka:latest",
        "desc": "Bus de mensajes KRaft que conecta todos los componentes. Los sensores publican eventos, los consumers los procesan.",
        "category": "core",
        "stack": "khainet",
    },
    {
        "name": "Kafka-UI",
        "container": "khainet-kafka-ui",
        "component": "Management",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.3",
        "port": 8089,
        "image": "provectuslabs/kafka-ui:latest",
        "desc": "Interfaz web para gestionar topics, ver mensajes y monitorizar el bus Kafka.",
        "category": "management",
        "stack": "khainet",
        "url": "http://172.26.10.98:8089",
    },
    # === Sensores reales ===
    {
        "name": "Zeek",
        "container": "khainet-zeek",
        "component": "Network Sensor",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.9",
        "port": None,
        "image": "zeek/zeek:7.0.0",
        "desc": "Sensor de red que procesa PCAPs y genera logs JSON (conn, dns, http, ssl, ssh). El 'ojo' de KhaiNet sobre la red.",
        "category": "sensor",
        "stack": "khainet",
    },
    {
        "name": "Suricata",
        "container": "khainet-suricata",
        "component": "IDS/IPS",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.10",
        "port": None,
        "image": "jasonish/suricata:7.0.0",
        "desc": "IDS que analiza PCAPs con reglas ET Open y genera eve.json con alertas, severidad y categorización MITRE ATT&CK.",
        "category": "sensor",
        "stack": "khainet",
    },
    {
        "name": "Wazuh",
        "container": "khainet-wazuh",
        "component": "HIDS/SIEM",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.11",
        "port": 1514,
        "image": "wazuh/wazuh-manager:4.7.0",
        "desc": "HIDS/SIEM manager con filebeat integrado. Monitoriza endpoints: file integrity, rootkits, logs de auth.",
        "category": "sensor",
        "stack": "khainet",
    },
    {
        "name": "Filebeat",
        "container": "khainet-filebeat",
        "component": "Log Shipper",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.12",
        "port": None,
        "image": "elastic/filebeat:7.16.3",
        "desc": "Shipper que lee logs de Zeek, Suricata y Wazuh y los envía a Kafka con routing por tipo de log.",
        "category": "sensor",
        "stack": "khainet",
    },
    # === Almacenamiento ===
    {
        "name": "OpenSearch",
        "container": "khainet-opensearch",
        "component": "Search & Storage",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.5",
        "port": 9200,
        "image": "opensearchproject/opensearch:2.16",
        "desc": "Data lake para logs. Indexa eventos de Zeek, alertas de Suricata y eventos de Wazuh. 153K+ docs indexados.",
        "category": "storage",
        "stack": "khainet",
    },
    {
        "name": "OpenSearch Dashboards",
        "container": "khainet-opensearch-dashboards",
        "component": "Visualization",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.4",
        "port": 5601,
        "image": "opensearchproject/opensearch-dashboards:2.16",
        "desc": "Interfaz web para crear dashboards y visualizaciones sobre los datos almacenados en OpenSearch.",
        "category": "storage",
        "stack": "khainet",
        "url": "http://172.26.10.98:5601",
    },
    {
        "name": "ClickHouse",
        "container": "khainet-clickhouse",
        "component": "Analytics DB",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.6",
        "port": 8123,
        "image": "clickhouse/clickhouse-server:24.8",
        "desc": "Base de datos columnar para analytics a alta velocidad. Almacena eventos de Zeek y métricas para consultas rápidas.",
        "category": "storage",
        "stack": "khainet",
    },
    # === Pipeline ===
    {
        "name": "Kafka Connect",
        "container": "khainet-kafka-connect",
        "component": "Sinks & Connectors",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.7",
        "port": 8083,
        "image": "khainet-kafka-connect:latest",
        "desc": "Kafka Connect 7.7.3 con plugin ClickHouse. 5 sink connectors que mueven datos de Kafka a ClickHouse y OpenSearch.",
        "category": "pipeline",
        "stack": "khainet",
        "url": "http://172.26.10.98:8083",
    },
    {
        "name": "Logstash",
        "container": "khainet-logstash",
        "component": "Kafka → OpenSearch",
        "status": "online",
        "host": "docker02",
        "ip": "172.25.0.8",
        "port": None,
        "image": "logstash:7.16.3",
        "desc": "Pipeline Logstash que consume de Kafka y envía a OpenSearch. Necesario porque el ES connector es incompatible con OpenSearch 2.x.",
        "category": "pipeline",
        "stack": "khainet",
    },
    # === IA (demo engine, no container) ===
    {
        "name": "Brain",
        "container": None,
        "component": "AI Correlation",
        "status": "online",
        "host": "demo",
        "ip": None,
        "port": 4200,
        "image": "khainet/brain:latest",
        "desc": "Capa de IA que correlaciona eventos de múltiples fuentes, asigna tácticas MITRE ATT&CK y genera narrativas de incidentes.",
        "category": "ai",
        "stack": None,
    },
    # === Planificados (no desplegados aún) ===
    {
        "name": "Shuffle",
        "container": None,
        "component": "SOAR",
        "status": "planned",
        "host": "docker02",
        "ip": None,
        "port": 3001,
        "image": "shuffle/shuffle:latest",
        "desc": "Orquestador de respuestas automatizadas (SOAR). Ejecuta playbooks cuando se detectan incidentes: aísla hosts, bloquea IPs, notifica al equipo.",
        "category": "soar",
        "stack": None,
    },
    {
        "name": "TheHive",
        "container": None,
        "component": "Incident Response",
        "status": "planned",
        "host": "docker03",
        "ip": None,
        "port": 9000,
        "image": "thehiveproject/thehive:latest",
        "desc": "Plataforma de gestión de incidentes. Crea casos, asigna tareas, hace seguimiento de investigaciones.",
        "category": "soar",
        "stack": None,
    },
    {
        "name": "MISP",
        "container": None,
        "component": "Threat Intel",
        "status": "planned",
        "host": "docker03",
        "ip": None,
        "port": 80,
        "image": "harvardit5/misp:latest",
        "desc": "Plataforma de inteligencia de amenazas. Comparte y consume IOCs (IPs, dominios, hashes maliciosos). Fuente de etiquetas para auto-etiquetado.",
        "category": "intel",
        "stack": None,
    },
]


# ===========================================================================
# InfraMonitor — consulta el estado real de containers y connectors
# ===========================================================================


class InfraMonitor:
    """Monitoriza el estado real de los containers del stack KhaiNet
    via Portainer API y los connectors de Kafka Connect via REST API."""

    def __init__(self):
        self._portainer_jwt: str | None = None
        self._jwt_expires: float = 0.0
        self._last_containers: dict[str, dict] = {}
        self._last_connectors: list[dict] = []
        self._last_check_containers: float = 0.0
        self._last_check_connectors: float = 0.0

    def _get_portainer_jwt(self) -> str | None:
        """Obtiene JWT de Portainer (cacheado hasta expirar)."""
        import os
        import requests as req

        now = time.time()
        if self._portainer_jwt and now < self._jwt_expires - 60:
            return self._portainer_jwt

        try:
            portainer_url = os.environ.get("PORTAINER_URL", "https://172.26.10.98:9443")
            portainer_user = os.environ.get("PORTAINER_USER", "admin")
            portainer_pass = os.environ.get("PORTAINER_PASS", "")
            if not portainer_pass:
                return None

            resp = req.post(
                f"{portainer_url}/api/auth",
                json={"Username": portainer_user, "Password": portainer_pass},
                verify=False,
                timeout=5,
            )
            if resp.status_code == 200:
                token = resp.json().get("jwt", "")
                self._portainer_jwt = token
                self._jwt_expires = now + 3600  # JWT válido 1h
                return token
        except Exception:
            pass
        return None

    def get_containers(self) -> dict[str, dict]:
        """Consulta el estado real de los containers via Portainer Docker API.
        Returns dict: container_name → {state, status, health, ip, image}
        """
        now = time.time()
        if now - self._last_check_containers < 10 and self._last_containers:
            return self._last_containers

        import requests as req
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        jwt = self._get_portainer_jwt()
        if not jwt:
            return self._last_containers

        try:
            portainer_url = "https://172.26.10.98:9443"
            headers = {"Authorization": f"Bearer {jwt}"}
            # endpointId=3 = docker02
            resp = req.get(
                f"{portainer_url}/api/endpoints/3/docker/containers/json?all=true",
                headers=headers,
                verify=False,
                timeout=8,
            )
            if resp.status_code != 200:
                return self._last_containers

            containers = resp.json()
            result = {}
            for c in containers:
                name = (c.get("Names", [""])[0] or "").lstrip("/")
                state = c.get("State", "unknown")
                status = c.get("Status", "")
                image = c.get("Image", "")

                # Extraer IP de la red khainet-network
                networks = c.get("NetworkSettings", {}).get("Networks", {})
                ip = None
                for net_name, net_info in networks.items():
                    if "khainet" in net_name:
                        ip = net_info.get("IPAddress", "")
                        break
                if not ip and networks:
                    # fallback a primera red
                    first_net = next(iter(networks.values()), {})
                    ip = first_net.get("IPAddress", "")

                # Health status
                health = None
                inspect_data = c.get("State", {})
                if isinstance(inspect_data, dict):
                    health_obj = inspect_data.get("Health", {})
                    if health_obj:
                        health = health_obj.get("Status", "")

                result[name] = {
                    "state": state,
                    "status": status,
                    "health": health,
                    "ip": ip,
                    "image": image,
                }

            self._last_containers = result
            self._last_check_containers = now
            return result
        except Exception:
            return self._last_containers

    def get_connectors(self) -> list[dict]:
        """Consulta el estado de los Kafka Connect connectors via REST API."""
        now = time.time()
        if now - self._last_check_connectors < 15 and self._last_connectors:
            return self._last_connectors

        import requests as req

        try:
            base = "http://172.26.10.98:8083"
            resp = req.get(f"{base}/connectors", timeout=5)
            if resp.status_code != 200:
                return self._last_connectors

            connector_names = resp.json()
            connectors = []
            for name in connector_names:
                try:
                    status_resp = req.get(f"{base}/connectors/{name}/status", timeout=5)
                    if status_resp.status_code == 200:
                        data = status_resp.json()
                        conn_state = data.get("connector", {}).get("state", "UNKNOWN")
                        tasks = data.get("tasks", [])
                        task_states = [
                            {
                                "id": f"{t.get('id', '?')}",
                                "state": t.get("state", "UNKNOWN"),
                                "trace": t.get("trace", "")[:200]
                                if t.get("trace")
                                else "",
                            }
                            for t in tasks
                        ]
                        all_running = (
                            all(t["state"] == "RUNNING" for t in task_states)
                            if task_states
                            else False
                        )
                        connectors.append(
                            {
                                "name": name,
                                "state": conn_state,
                                "tasks": task_states,
                                "healthy": conn_state == "RUNNING" and all_running,
                            }
                        )
                except Exception:
                    connectors.append(
                        {
                            "name": name,
                            "state": "UNKNOWN",
                            "tasks": [],
                            "healthy": False,
                        }
                    )

            self._last_connectors = connectors
            self._last_check_connectors = now
            return connectors
        except Exception:
            return self._last_connectors


infra_monitor = InfraMonitor()


@app.get("/api/network/topology")
async def get_topology():
    """Topología de red: zonas, dispositivos, conexiones e incidentes."""
    return JSONResponse(NETWORK_TOPOLOGY)


@app.get("/api/network/devices")
async def get_devices():
    """Inventario de dispositivos de red."""
    return JSONResponse({"devices": NETWORK_TOPOLOGY["devices"]})


@app.get("/api/network/incidents")
async def get_incidents():
    """Incidentes activos y historicos."""
    return JSONResponse({"incidents": NETWORK_TOPOLOGY["incidents"]})


@app.get("/api/network/active-links")
async def get_active_links():
    """Enlaces activos en el mapa de red (eventos con score alto en tiempo real)."""
    return JSONResponse({"active_links": engine._active_links})


@app.get("/api/infra/services")
async def get_infra_services():
    """Estado de los servicios de infraestructura del stack KhaiNet."""
    # Merge con estado real de containers si está disponible
    containers = infra_monitor.get_containers()
    services = []
    for s in INFRA_SERVICES:
        svc = dict(s)
        cname = s.get("container")
        if cname and cname in containers:
            c = containers[cname]
            svc["real_status"] = c["state"]
            svc["real_health"] = c.get("health")
            svc["real_ip"] = c.get("ip") or s.get("ip")
            svc["real_image"] = c.get("image", "")
            # Override status si el container está parado
            if c["state"] == "running":
                svc["status"] = "online"
            elif c["state"] in ("exited", "paused"):
                svc["status"] = "offline"
        services.append(svc)
    return JSONResponse({"services": services})


@app.get("/api/infra/containers")
async def get_infra_containers():
    """Estado real de los containers del stack KhaiNet via Portainer API."""
    containers = infra_monitor.get_containers()
    # Filtrar solo los containers khainet
    khainet_containers = {
        name: info for name, info in containers.items() if "khainet" in name
    }
    return JSONResponse(
        {
            "containers": khainet_containers,
            "stack": "khainet",
            "stack_id": 24,
            "endpoint": "docker02 (3)",
            "total": len(khainet_containers),
            "running": sum(
                1 for c in khainet_containers.values() if c["state"] == "running"
            ),
        }
    )


@app.get("/api/infra/connectors")
async def get_infra_connectors():
    """Estado de los Kafka Connect connectors via REST API."""
    connectors = infra_monitor.get_connectors()
    running = sum(1 for c in connectors if c.get("healthy"))
    failed = sum(1 for c in connectors if not c.get("healthy"))
    return JSONResponse(
        {
            "connectors": connectors,
            "total": len(connectors),
            "running": running,
            "failed": failed,
            "connect_url": "http://172.26.10.98:8083",
        }
    )


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    engine.subscribers.append(ws)
    # Send initial state
    await ws.send_json(
        {
            "type": "init",
            "stats": engine.get_stats(),
            "source_stats": engine._serialize_source_stats(),
            "events": engine.recent_events[:15],
            "labels": engine.recent_labels[:10],
            "active_learning": engine.active_learning_queue[:5],
        }
    )
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in engine.subscribers:
            engine.subscribers.remove(ws)


if __name__ == "__main__":
    print("=" * 60)
    print("  KhaiNet Demo — Detection + Auto-Labeling Dashboard")
    print("  http://localhost:4200")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=4200, log_level="warning")
