# Feature Engineering Pipeline — KhaiNet Detection

## Overview

This document describes the complete feature engineering pipeline for the
KhaiNet detection module. The pipeline transforms raw Zeek logs into
feature vectors suitable for three anomaly detection models: Isolation
Forest, Autoencoder, and HMM.

## Zeek Log Types

The pipeline ingests four types of Zeek logs:

### conn.log (Connections)
| Field | Type | Description |
|-------|------|-------------|
| ts | time | Connection timestamp |
| uid | string | Unique connection ID |
| id.orig_h | addr | Source IP (pseudonymized) |
| id.orig_p | port | Source port |
| id.resp_h | addr | Destination IP (pseudonymized) |
| id.resp_p | port | Destination port |
| proto | enum | Protocol (tcp, udp, icmp) |
| service | string | Service (http, ssl, ssh, dns, etc.) |
| duration | interval | Connection duration (seconds) |
| orig_bytes | count | Bytes from source |
| resp_bytes | count | Bytes from destination |
| conn_state | string | Connection state (SF, S0, REJ, etc.) |
| orig_pkts | count | Packets from source |
| resp_pkts | count | Packets from destination |

### dns.log (DNS Queries)
| Field | Type | Description |
|-------|------|-------------|
| ts | time | Query timestamp |
| uid | string | Unique query ID |
| query | string | Domain queried |
| qclass | count | Query class |
| qtype_name | string | Query type (A, AAAA, TXT, etc.) |
| rcode | string | Response code (NOERROR, NXDOMAIN, etc.) |
| answers | vector[string] | DNS answers |
| ttl | vector[int] | TTL values |

### http.log (HTTP Requests)
| Field | Type | Description |
|-------|------|-------------|
| ts | time | Request timestamp |
| method | string | HTTP method (GET, POST, etc.) |
| host | string | Host header |
| uri | string | Request URI |
| user_agent | string | User-Agent header |
| status_code | count | HTTP status code |
| request_body_len | count | Request body size |
| response_body_len | count | Response body size |

### ssl.log (SSL/TLS Handshakes)
| Field | Type | Description |
|-------|------|-------------|
| ts | time | Handshake timestamp |
| version | string | TLS version |
| cipher | string | Cipher suite |
| server_name | string | SNI (Server Name Indication) |
| resumed | bool | Session resumed |
| subject | string | Certificate subject |
| issuer | string | Certificate issuer |

## Feature Extraction

### Per-Event Features (FeatureVector)

Each ZeekConn event is transformed into a FeatureVector with 17 features:

#### Connection Features (7)
| Feature | Description | Source |
|---------|-------------|--------|
| duration | Connection duration | conn.duration |
| orig_bytes | Bytes from source | conn.orig_bytes |
| resp_bytes | Bytes from destination | conn.resp_bytes |
| orig_pkts | Packets from source | conn.orig_pkts |
| resp_pkts | Packets from destination | conn.resp_pkts |
| bytes_total | Total bytes (orig + resp) | computed |
| bytes_ratio | orig_bytes / bytes_total | computed |

#### Destination Features (2)
| Feature | Description | Source |
|---------|-------------|--------|
| dst_port | Destination port | conn.dst_port |
| is_common_port | Port in {80, 443, 22, 53, 25, 445, 3389} | computed |

#### Temporal Features (3)
| Feature | Description | Source |
|---------|-------------|--------|
| hour_of_day | Hour of day (0-23) | conn.timestamp |
| day_of_week | Day of week (0-6) | conn.timestamp |
| is_weekend | Saturday or Sunday | computed |

#### Host-Aggregated Features (5)
| Feature | Description | Source |
|---------|-------------|--------|
| unique_destinations | Unique dst IPs per src_ip | aggregated |
| unique_ports | Unique dst ports per src_ip | aggregated |
| dns_queries_count | DNS queries per src_ip | dns.log |
| nxdomain_ratio | NXDOMAIN / total DNS queries | dns.log |
| avg_dns_query_length | Average DNS query length | dns.log |

### Window Features (WindowFeatures) — for HMM

Events are grouped by src_ip and 5-minute windows:

| Feature | Description |
|---------|-------------|
| bytes_out | Sum of orig_bytes in window |
| bytes_in | Sum of resp_bytes in window |
| pkts_total | Sum of all packets in window |
| unique_destinations | Unique dst IPs in window |
| unique_ports | Unique dst ports in window |
| dns_queries | DNS queries in window |
| nxdomain_ratio | NXDOMAIN / total DNS in window |
| avg_duration | Average connection duration |
| connection_count | Number of connections in window |

## Normalization

Features are normalized using **StandardScaler** (z-score normalization):

```
x_normalized = (x - mean) / std
```

- The scaler is **fitted on training data** and reused for inference
- Bool features (is_common_port, is_weekend) are converted to 0/1 before scaling
- The fitted scaler is persisted alongside the models

## Features per Model

### Isolation Forest (IF)
- **Input**: 17 normalized features (FeatureVector.normalized)
- **Output**: Anomaly score 0-1 (higher = more anomalous)
- **Score normalization**: `(max_score - raw_score) / (max_score - min_score)`
- **Threshold**: Configurable (default 0.7)

### Autoencoder (AE)
- **Input**: 17 normalized features (FeatureVector.normalized)
- **Architecture**: input → 64 → 32 → 16 → 32 → 64 → input (configurable)
- **Output**: Reconstruction error → score 0-1
- **Threshold**: p99 of training reconstruction errors
- **Score**: `min(1.0, error / (threshold * 2))`

### HMM
- **Input**: 5 window features: [bytes_out, unique_destinations, pkts_total, nxdomain_ratio, avg_duration]
- **States**: 4 hidden states (unsupervised)
- **State mapping** (post-training):
  - Lowest bytes_out + fewest destinations → **normal**
  - Most unique destinations → **scan**
  - Highest bytes_out → **exfil**
  - Remaining state → **c2**
- **Output**: Score based on state label and log-likelihood

## Training Process

```
1. Zeek logs (conn, dns, http, ssl)
        ↓
2. Feature Engineering
   ├── extract_event_features() → FeatureVector[] (for IF, AE)
   └── extract_window_features() → WindowFeatures[] (for HMM)
        ↓
3. Normalization (StandardScaler fit + transform)
        ↓
4. Train Models
   ├── IsolationForest.fit(FeatureVectors)
   ├── Autoencoder.fit(FeatureVectors)
   └── HMM.fit(WindowFeatures)
        ↓
5. Baseline Calculation
   └── BaselineCalculator.calculate_baseline(conn, dns)
        ↓
6. HMM State Mapping
   └── HMM.map_states(baseline) → StateMapping[]
```

## Inference Process

```
1. Zeek logs (conn, dns, http, ssl)
        ↓
2. Feature Engineering (same as training)
        ↓
3. Normalization (using saved scaler)
        ↓
4. Predict
   ├── IF.predict() → ModelResult[]
   ├── AE.predict() → ModelResult[]
   └── HMM.predict() → ModelResult[]
        ↓
5. Individual scores (NO fusion — fusion is in tuning/)
```

## Baseline Statistical

The baseline calculator computes per-host, per-service statistics:

- **Metrics**: bytes_out, bytes_in, duration, unique_destinations, unique_ports, pkts_total, dns_queries
- **Statistics**: mean, std, min, max, p50, p95, p99
- **Window**: 24 hours (configurable)
- **Comparison**: z-scores and ratio vs p99 for individual events

## Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Zeek Logs                                │
│  conn.log  │  dns.log  │  http.log  │  ssl.log                  │
└─────┬──────┴─────┬─────┴──────┬─────┴──────┬────────────────────┘
      │            │            │            │
      ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    zeek_parser.py                                │
│  Parse TSV → Pydantic models (ZeekConn, ZeekDNS, etc.)          │
│  Pseudonymize IPs (SHA-256 + salt)                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                  feature_engineering.py                          │
│  ┌─────────────────────┐  ┌──────────────────────────┐         │
│  │ extract_event_      │  │ extract_window_features  │         │
│  │ features()          │  │ (5-min windows)          │         │
│  │ → FeatureVector[]   │  │ → WindowFeatures[]       │         │
│  └──────────┬──────────┘  └────────────┬─────────────┘         │
│             │                           │                       │
│  ┌──────────▼──────────┐               │                       │
│  │ normalize_features()│               │                       │
│  │ StandardScaler      │               │                       │
│  └──────────┬──────────┘               │                       │
└─────────────┼──────────────────────────┼───────────────────────┘
              │                          │
    ┌─────────┴────────┐        ┌────────┴────────┐
    ▼                  ▼        ▼                 │
┌────────┐      ┌──────────┐  ┌────────┐         │
│  IF    │      │   AE     │  │  HMM   │         │
│ (sklearn)│    │ (PyTorch)│  │(hmmlearn)│       │
└───┬────┘      └────┬─────┘  └───┬────┘         │
    │                │            │               │
    ▼                ▼            ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                    orchestrator.py                            │
│  ModelResult[] (individual scores, NO fusion)                │
│  + BaselineCalculator (stats per host/service)               │
│  + HMM StateMapping (normal, scan, exfil, c2)                │
└───────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    tuning/ module
              (score fusion + threshold tuning)
```
