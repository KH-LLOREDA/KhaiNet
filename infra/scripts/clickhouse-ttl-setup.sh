#!/bin/bash
# ============================================================
# KhaiNet — ClickHouse TTL Setup
# ============================================================
# Reduce los TTLs de las tablas de ClickHouse para fase de desarrollo.
# Los TTLs originales (180d/365d) son excesivos para desarrollo.
#
# Nuevos TTLs (fase desarrollo):
#   - Tablas de eventos (zeek-*, dns/http/ssl_events, network_flows): 30d
#   - Tablas de ML (ml-scores, ml_scores, ml_features): 30d
#   - Tablas de baselines: 90d
#   - Materialized views (traffic_hourly_*): 90d
#
# En producción, aumentar a 90d (eventos) / 180d (baselines) / 365d (agregados).
#
# Uso: ./clickhouse-ttl-setup.sh [clickhouse_container]
# ============================================================

set -euo pipefail

CH_CONTAINER="${1:-khainet-clickhouse}"
CH_USER="admin"
CH_PASS="Khainet2025!Secure"

echo "=== KhaiNet — ClickHouse TTL Setup ==="
echo "  Container: $CH_CONTAINER"
echo ""

# Verificar que ClickHouse está corriendo
if ! docker ps --format '{{.Names}}' | grep -q "$CH_CONTAINER"; then
    echo "ERROR: Container $CH_CONTAINER no está corriendo"
    exit 1
fi

ch() {
    docker exec "$CH_CONTAINER" clickhouse-client --user "$CH_USER" --password "$CH_PASS" --query "$1" 2>/dev/null
}

# --- Tablas de eventos: 30d ---
echo "--- Actualizando TTL a 30d para tablas de eventos ---"

# zeek-conn
ch "ALTER TABLE khainet.\`zeek-conn\` MODIFY TTL toDateTime(ingest_ts) + toIntervalDay(30)" && echo "  zeek-conn: 30d ✓" || echo "  zeek-conn: skip (no data or error)"

# zeek-dns
ch "ALTER TABLE khainet.\`zeek-dns\` MODIFY TTL toDateTime(ingest_ts) + toIntervalDay(30)" && echo "  zeek-dns: 30d ✓" || echo "  zeek-dns: skip"

# zeek-http
ch "ALTER TABLE khainet.\`zeek-http\` MODIFY TTL toDateTime(ingest_ts) + toIntervalDay(30)" && echo "  zeek-http: 30d ✓" || echo "  zeek-http: skip"

# zeek-ssl
ch "ALTER TABLE khainet.\`zeek-ssl\` MODIFY TTL toDateTime(ingest_ts) + toIntervalDay(30)" && echo "  zeek-ssl: 30d ✓" || echo "  zeek-ssl: skip"

# dns_events
ch "ALTER TABLE khainet.dns_events MODIFY TTL toDateTime(timestamp) + toIntervalDay(30)" && echo "  dns_events: 30d ✓" || echo "  dns_events: skip"

# http_events
ch "ALTER TABLE khainet.http_events MODIFY TTL toDateTime(timestamp) + toIntervalDay(30)" && echo "  http_events: 30d ✓" || echo "  http_events: skip"

# ssl_events
ch "ALTER TABLE khainet.ssl_events MODIFY TTL toDateTime(timestamp) + toIntervalDay(30)" && echo "  ssl_events: 30d ✓" || echo "  ssl_events: skip"

# network_flows
ch "ALTER TABLE khainet.network_flows MODIFY TTL toDateTime(timestamp) + toIntervalDay(30)" && echo "  network_flows: 30d ✓" || echo "  network_flows: skip"

echo ""

# --- Tablas de ML: 30d ---
echo "--- Actualizando TTL a 30d para tablas de ML ---"

# ml-scores (con guion)
ch "ALTER TABLE khainet.\`ml-scores\` MODIFY TTL toDateTime(ingest_ts) + toIntervalDay(30)" && echo "  ml-scores: 30d ✓" || echo "  ml-scores: skip"

# ml_scores (con underscore)
ch "ALTER TABLE khainet.ml_scores MODIFY TTL toDateTime(timestamp) + toIntervalDay(30)" && echo "  ml_scores: 30d ✓" || echo "  ml_scores: skip"

# ml_features
ch "ALTER TABLE khainet.ml_features MODIFY TTL toDateTime(timestamp) + toIntervalDay(30)" && echo "  ml_features: 30d ✓" || echo "  ml_features: skip"

echo ""

# --- Baselines: 90d ---
echo "--- Actualizando TTL a 90d para baselines ---"
ch "ALTER TABLE khainet.baselines MODIFY TTL toDateTime(timestamp) + toIntervalDay(90)" && echo "  baselines: 90d ✓" || echo "  baselines: skip"

echo ""

# --- Materialized views: 90d ---
echo "--- Actualizando TTL a 90d para materialized views ---"
# Las MVs tienen tablas inner, necesitamos alterar las tablas inner
INNER_TABLES=$(ch "SELECT name FROM system.tables WHERE database='khainet' AND engine LIKE '%MergeTree%' AND name LIKE '.inner_id.%'" 2>/dev/null || echo "")
if [ -n "$INNER_TABLES" ]; then
    echo "$INNER_TABLES" | while read tname; do
        if [ -n "$tname" ]; then
            ch "ALTER TABLE khainet.\`$tname\` MODIFY TTL toDateTime(hour) + toIntervalDay(90)" && echo "  $tname: 90d ✓" || echo "  $tname: skip"
        fi
    done
fi

echo ""

# --- Verificar ---
echo "=== Verificación ==="
echo "--- TTLs actuales ---"
ch "SELECT name, extractGroups(create_table_query, 'TTL (.*?)( SETTINGS|$)')[1] as ttl FROM system.tables WHERE database='khainet' AND create_table_query LIKE '%TTL%' ORDER BY name" 2>/dev/null || \
ch "SELECT name FROM system.tables WHERE database='khainet' AND create_table_query LIKE '%TTL%' ORDER BY name" 2>/dev/null

echo ""
echo "--- Tamaños actuales ---"
ch "SELECT name, formatReadableSize(total_bytes) as size, total_rows FROM system.tables WHERE database='khainet' AND total_bytes > 0 ORDER BY total_bytes DESC"

echo ""
echo "=== ClickHouse TTL Setup completado ==="
