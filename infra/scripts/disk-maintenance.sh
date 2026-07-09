#!/bin/bash
# ============================================================
# KhaiNet — Mantenimiento global de disco
# ============================================================
# Monitoriza el uso de disco de todos los componentes del stack
# y toma acciones preventivas para evitar que se llene el disco.
#
# Componentes monitorizados:
#   - Kafka (retención por topic)
#   - OpenSearch (índices, ISM)
#   - ClickHouse (tablas, TTL)
#   - Docker container logs (json logs)
#   - Volúmenes de sensores (Zeek, Suricata, Wazuh)
#
# Niveles de alerta:
#   - < 70%: Normal
#   - 70-85%: Warning — reducir retención de Kafka a 6h
#   - 85-95%: Critical — purga agresiva (Kafka 1h, forzar ISM, truncar logs Docker)
#   - > 95%: Emergency — purga máxima + eliminar índices viejos OpenSearch
#
# Uso:
#   ./disk-maintenance.sh              — modo normal (reporta + actúa si necesario)
#   ./disk-maintenance.sh --dry-run    — solo reporta, no actúa
#   ./disk-maintenance.sh --force      — fuerza purga agresiva
#
# Recomendado en cron: 0 */4 * * * /path/to/disk-maintenance.sh >> /var/log/khainet/disk-maintenance.log 2>&1
# ============================================================

set -euo pipefail

# --- Configuración ---
KAFKA_CONTAINER="khainet-kafka"
OPENSEARCH_CONTAINER="khainet-opensearch"
CLICKHOUSE_CONTAINER="khainet-clickhouse"
OS_URL="http://localhost:9200"
OS_USER="admin"
OS_PASS="Khainet2025Secure"
KAFKA_BOOTSTRAP="localhost:9092"
CH_USER="admin"
CH_PASS="Khainet2025!Secure"

WARNING_THRESHOLD=70
CRITICAL_THRESHOLD=85
EMERGENCY_THRESHOLD=95

DRY_RUN=false
FORCE_PURGE=false

# Parse args
for arg in "$@"; do
    case $arg in
        --dry-run)  DRY_RUN=true ;;
        --force)    FORCE_PURGE=true ;;
    esac
done

# --- Helpers ---
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

docker_exec() {
    local container="$1"; shift
    docker exec "$container" sh -c "$*" 2>/dev/null
}

get_disk_usage_pct() {
    df -h / | awk 'NR==2 {gsub("%","",$5); print $5}'
}

# --- Inicio ---
log "=== KhaiNet Disk Maintenance ==="
log "Mode: $([ "$DRY_RUN" = true ] && echo 'DRY-RUN' || echo 'ACTIVE')$([ "$FORCE_PURGE" = true ] && echo ' + FORCE')"
echo ""

# ============================================================
# 1. Disco del host
# ============================================================
DISK_PCT=$(get_disk_usage_pct)
log "Host disk usage: ${DISK_PCT}%"
df -h / | head -2
echo ""

if [ "$FORCE_PURGE" = true ]; then
    DISK_PCT=90  # Forzar nivel critical
    log "FORCE mode: tratando como critical (${DISK_PCT}%)"
fi

# ============================================================
# 2. Docker container logs (json logs)
# ============================================================
log "--- Docker container logs ---"
LOG_DIR="/var/lib/docker/containers"
if [ -d "$LOG_DIR" ]; then
    TOTAL_LOG_SIZE=$(du -sh "$LOG_DIR" 2>/dev/null | awk '{print $1}')
    log "  Total Docker logs: $TOTAL_LOG_SIZE"

    # Top 5 contenedores por tamaño de log
    du -sh "$LOG_DIR"/*/*-json.log 2>/dev/null | sort -rh | head -5 | while read line; do
        log "  $line"
    done

    # Si > critical, truncar logs grandes
    if [ "$DISK_PCT" -ge "$CRITICAL_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  ⚠ CRITICAL: Truncando logs Docker > 100MB..."
        find "$LOG_DIR" -name "*-json.log" -size +100M -exec truncate -s 0 {} \; 2>/dev/null
        log "  Logs truncados."
    fi
fi
echo ""

# ============================================================
# 3. Kafka
# ============================================================
log "--- Kafka ---"
if docker ps --format '{{.Names}}' | grep -q "$KAFKA_CONTAINER"; then
    KAFKA_DATA_SIZE=$(docker_exec "$KAFKA_CONTAINER" "du -sh /var/lib/kafka/data 2>/dev/null | awk '{print \$1}'" || echo "N/A")
    log "  Kafka data: $KAFKA_DATA_SIZE"

    # Listar topics con tamaño
    docker_exec "$KAFKA_CONTAINER" "/opt/kafka/bin/kafka-topics.sh --bootstrap-server $KAFKA_BOOTSTRAP --list 2>/dev/null" | while read topic; do
        if [ -n "$topic" ]; then
            log "  Topic: $topic"
        fi
    done

    if [ "$DISK_PCT" -ge "$EMERGENCY_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  🚨 EMERGENCY: Purga máxima Kafka (retención 1h)..."
        for topic in zeek-conn zeek-dns zeek-http zeek-ssl suricata-alerts wazuh-events ml-scores brain-incidents; do
            docker_exec "$KAFKA_CONTAINER" "/opt/kafka/bin/kafka-configs.sh --bootstrap-server $KAFKA_BOOTSTRAP --alter --entity-type topics --entity-name $topic --add-config retention.ms=3600000 2>/dev/null" || true
        done
        log "  Retención Kafka reducida a 1h."
    elif [ "$DISK_PCT" -ge "$CRITICAL_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  ⚠ CRITICAL: Reduciendo retención Kafka a 6h..."
        for topic in zeek-conn zeek-dns zeek-http zeek-ssl suricata-alerts wazuh-events; do
            docker_exec "$KAFKA_CONTAINER" "/opt/kafka/bin/kafka-configs.sh --bootstrap-server $KAFKA_BOOTSTRAP --alter --entity-type topics --entity-name $topic --add-config retention.ms=21600000 2>/dev/null" || true
        done
        log "  Retención Kafka reducida a 6h para topics de sensores."
    elif [ "$DISK_PCT" -ge "$WARNING_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  ⚠ WARNING: Reduciendo retención zeek-conn a 6h..."
        docker_exec "$KAFKA_CONTAINER" "/opt/kafka/bin/kafka-configs.sh --bootstrap-server $KAFKA_BOOTSTRAP --alter --entity-type topics --entity-name zeek-conn --add-config retention.ms=21600000 2>/dev/null" || true
    fi
else
    log "  Kafka container not running"
fi
echo ""

# ============================================================
# 4. OpenSearch
# ============================================================
log "--- OpenSearch ---"
if docker ps --format '{{.Names}}' | grep -q "$OPENSEARCH_CONTAINER"; then
    OS_DATA_SIZE=$(docker_exec "$OPENSEARCH_CONTAINER" "du -sh /usr/share/opensearch/data 2>/dev/null | awk '{print \$1}'" || echo "N/A")
    log "  OpenSearch data: $OS_DATA_SIZE"

    # Tamaño por índice
    docker_exec "$OPENSEARCH_CONTAINER" "curl -s -u $OS_USER:$OS_PASS '$OS_URL/_cat/indices?v&s=store.size:desc&h=index,docs.count,store.size' 2>/dev/null" | head -10 | while read line; do
        log "  $line"
    done

    if [ "$DISK_PCT" -ge "$CRITICAL_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  ⚠ CRITICAL: Forzando borrado de índices viejos..."
        # Forzar ISM a evaluar transiciones inmediatamente
        docker_exec "$OPENSEARCH_CONTAINER" "curl -s -X POST -u $OS_USER:$OS_PASS '$OS_URL/_plugins/_ism/explain/zeek-*,brain-*,wazuh-*,suricata-*' 2>/dev/null" || true
        # Reducir retención ISM a 7d temporalmente
        # (Las policies se actualizan via API)
    fi

    if [ "$DISK_PCT" -ge "$EMERGENCY_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  🚨 EMERGENCY: Eliminando índices > 7 días..."
        # Obtener índices con edad > 7d y eliminarlos
        docker_exec "$OPENSEARCH_CONTAINER" "curl -s -u $OS_USER:$OS_PASS '$OS_URL/_cat/indices/zeek-*,brain-*,wazuh-*,suricata-*?h=index,creation.date' 2>/dev/null" | while read idx_name creation_date; do
            if [ -n "$creation_date" ]; then
                age_days=$(( ( $(date +%s) - $((creation_date / 1000)) ) / 86400 ))
                if [ "$age_days" -gt 7 ]; then
                    log "  Eliminando índice $idx_name (edad: ${age_days}d)..."
                    docker_exec "$OPENSEARCH_CONTAINER" "curl -s -X DELETE -u $OS_USER:$OS_PASS '$OS_URL/$idx_name' 2>/dev/null" || true
                fi
            fi
        done
    fi
else
    log "  OpenSearch container not running"
fi
echo ""

# ============================================================
# 5. ClickHouse
# ============================================================
log "--- ClickHouse ---"
if docker ps --format '{{.Names}}' | grep -q "$CLICKHOUSE_CONTAINER"; then
    CH_DATA_SIZE=$(docker_exec "$CLICKHOUSE_CONTAINER" "du -sh /var/lib/clickhouse/data 2>/dev/null | awk '{print \$1}'" || echo "N/A")
    CH_LOGS_SIZE=$(docker_exec "$CLICKHOUSE_CONTAINER" "du -sh /var/log/clickhouse-server 2>/dev/null | awk '{print \$1}'" || echo "N/A")
    log "  ClickHouse data: $CH_DATA_SIZE, logs: $CH_LOGS_SIZE"

    # Tablas con tamaño
    docker_exec "$CLICKHOUSE_CONTAINER" "clickhouse-client --user $CH_USER --password '$CH_PASS' --query \"SELECT name, formatReadableSize(total_bytes) as size, total_rows FROM system.tables WHERE database='khainet' AND total_bytes > 0 ORDER BY total_bytes DESC LIMIT 10\" 2>/dev/null" | while read line; do
        log "  $line"
    done

    if [ "$DISK_PCT" -ge "$CRITICAL_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
        log "  ⚠ CRITICAL: Forzando optimización y purga de particiones viejas..."
        # Forzar TTL merge
        docker_exec "$CLICKHOUSE_CONTAINER" "clickhouse-client --user $CH_USER --password '$CH_PASS' --query \"OPTIMIZE TABLE khainet.\\\`zeek-conn\\\` FINAL\" 2>/dev/null" || true
        # Limpiar logs viejos de ClickHouse
        docker_exec "$CLICKHOUSE_CONTAINER" "find /var/log/clickhouse-server -name '*.log' -mtime +7 -delete 2>/dev/null" || true
    fi
else
    log "  ClickHouse container not running"
fi
echo ""

# ============================================================
# 6. Volúmenes de sensores
# ============================================================
log "--- Sensores ---"
for container in khainet-zeek khainet-suricata khainet-wazuh; do
    if docker ps --format '{{.Names}}' | grep -q "$container"; then
        case $container in
            khainet-zeek)
                SIZE=$(docker_exec "$container" "du -sh /data/logs /data/pcap 2>/dev/null" || echo "N/A")
                ;;
            khainet-suricata)
                SIZE=$(docker_exec "$container" "du -sh /var/log/suricata /data/pcap 2>/dev/null" || echo "N/A")
                ;;
            khainet-wazuh)
                SIZE=$(docker_exec "$container" "du -sh /var/ossec/logs /var/ossec/queue 2>/dev/null" || echo "N/A")
                ;;
        esac
        log "  $container: $SIZE"

        if [ "$DISK_PCT" -ge "$CRITICAL_THRESHOLD" ] && [ "$DRY_RUN" = false ]; then
            case $container in
                khainet-zeek)
                    log "    Purgando logs Zeek > 3 días..."
                    docker_exec "$container" "find /data/logs -name '*.log' -mtime +3 -delete 2>/dev/null" || true
                    docker_exec "$container" "find /data/pcap -name '*.pcap' -mtime +1 -delete 2>/dev/null" || true
                    ;;
                khainet-suricata)
                    log "    Purgando logs Suricata > 3 días..."
                    docker_exec "$container" "find /var/log/suricata -name '*.log' -mtime +3 -delete 2>/dev/null" || true
                    docker_exec "$container" "find /data/pcap -name '*.pcap' -mtime +1 -delete 2>/dev/null" || true
                    ;;
                khainet-wazuh)
                    log "    Purgando logs Wazuh > 7 días..."
                    docker_exec "$container" "find /var/ossec/logs -name '*.log' -mtime +7 -delete 2>/dev/null" || true
                    ;;
            esac
        fi
    fi
done
echo ""

# ============================================================
# 7. Restaurar retención normal si el disco está sano
# ============================================================
if [ "$DISK_PCT" -lt "$WARNING_THRESHOLD" ] && [ "$FORCE_PURGE" = false ]; then
    if [ -f "$(dirname "$0")/kafka-retention-config.sh" ]; then
        log "--- Disco sano (${DISK_PCT}%): restaurando retención normal de Kafka ---"
        if [ "$DRY_RUN" = false ]; then
            bash "$(dirname "$0")/kafka-retention-config.sh" 2>/dev/null || true
        fi
    fi
fi

# ============================================================
# Resumen
# ============================================================
log "=== Resumen ==="
log "  Disco: ${DISK_PCT}% $([ "$DISK_PCT" -ge "$EMERGENCY_THRESHOLD" ] && echo '🚨 EMERGENCY' || ([ "$DISK_PCT" -ge "$CRITICAL_THRESHOLD" ] && echo '⚠ CRITICAL' || ([ "$DISK_PCT" -ge "$WARNING_THRESHOLD" ] && echo '⚠ WARNING' || echo '✅ OK')))"
log "=== Mantenimiento completado ==="
