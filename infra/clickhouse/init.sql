-- KhaiNet — ClickHouse schema inicial
-- Tablas para analytics y feature engineering
-- Retención: 180 días (TTL por tabla, alineado con Zeek)

CREATE DATABASE IF NOT EXISTS khainet;

-- ───────────────────────────────────────────────────────────────
-- Tabla: network_flows — features de flujos de red (Zeek conn.log)
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.network_flows
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    src_ip            String,
    dst_ip            String,
    src_port          UInt16,
    dst_port          UInt16,
    protocol          LowCardinality(String),
    duration          Float64,
    orig_bytes        UInt64,
    resp_bytes        UInt64,
    orig_pkts         UInt32,
    resp_pkts         UInt32,
    service           LowCardinality(String),
    conn_state        LowCardinality(String),
    -- Features calculadas
    bytes_total       UInt64 MATERIALIZED orig_bytes + resp_bytes,
    pkts_total        UInt32 MATERIALIZED orig_pkts + resp_pkts,
    bytes_ratio       Float64 MATERIALIZED IF(resp_bytes = 0, 1.0, orig_bytes / resp_bytes),
    -- Metadata
    sensor_id         LowCardinality(String),
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Tabla: dns_events — features de eventos DNS (Zeek dns.log)
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.dns_events
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    src_ip            String,
    dst_ip            String,
    query             String,
    query_type        LowCardinality(String),
    rcode             LowCardinality(String),
    response_time_ms  Float32,
    ttl               Int32,
    answer            String,
    sensor_id         LowCardinality(String),
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, query)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Tabla: http_events — features de eventos HTTP (Zeek http.log)
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.http_events
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    src_ip            String,
    dst_ip            String,
    method            LowCardinality(String),
    uri               String,
    status_code       UInt16,
    request_len       UInt32,
    response_len      UInt32,
    user_agent        String,
    content_type      String,
    sensor_id         LowCardinality(String),
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Tabla: ssl_events — features de eventos SSL/TLS (Zeek ssl.log)
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.ssl_events
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    src_ip            String,
    dst_ip            String,
    version           LowCardinality(String),
    cipher            LowCardinality(String),
    server_name       String,
    subject           String,
    issuer            String,
    valid_from        DateTime,
    valid_to          DateTime,
    sensor_id         LowCardinality(String),
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Tabla: ml_features — features pre-calculadas para modelos ML
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.ml_features
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    src_ip            String,
    feature_name      LowCardinality(String),
    feature_value     Float64,
    window_start      DateTime64(3),
    window_end        DateTime64(3),
    sensor_id         LowCardinality(String),
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, feature_name)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Tabla: ml_scores — scores de anomalía de los modelos
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.ml_scores
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    src_ip            String,
    model_name        LowCardinality(String),
    score             Float64,
    is_anomaly        UInt8,
    threshold         Float64,
    features_json     String,
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, model_name)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Tabla: baselines — baselines estadísticos por host/ventana
-- ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS khainet.baselines
(
    timestamp         DateTime64(3) CODEC(Delta, ZSTD),
    entity            String,
    entity_type       LowCardinality(String),
    metric            LowCardinality(String),
    mean              Float64,
    stddev            Float64,
    p50               Float64,
    p95               Float64,
    p99               Float64,
    sample_count      UInt32,
    window_hours      UInt16,
    ingest_ts         DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (entity, metric, window_hours, timestamp)
TTL toDateTime(timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ───────────────────────────────────────────────────────────────
-- Vista materializada: agregación horaria de tráfico por IP origen
-- ───────────────────────────────────────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS khainet.traffic_hourly_by_src
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, src_ip)
TTL toDateTime(hour) + INTERVAL 365 DAY
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    src_ip,
    count()                   AS flow_count,
    sum(bytes_total)          AS bytes_total,
    sum(pkts_total)           AS pkts_total,
    uniqExact(dst_ip)         AS unique_dst_ips,
    uniqExact(dst_port)       AS unique_dst_ports
FROM khainet.network_flows
GROUP BY hour, src_ip;

-- ───────────────────────────────────────────────────────────────
-- Vista materializada: agregación horaria de tráfico por IP destino
-- ───────────────────────────────────────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS khainet.traffic_hourly_by_dst
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, dst_ip)
TTL toDateTime(hour) + INTERVAL 365 DAY
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    dst_ip,
    count()                   AS flow_count,
    sum(bytes_total)          AS bytes_total,
    sum(pkts_total)           AS pkts_total,
    uniqExact(src_ip)         AS unique_src_ips
FROM khainet.network_flows
GROUP BY hour, dst_ip;
