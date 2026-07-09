#!/bin/bash
# ==============================================================================
# KhaiNet — Mantenimiento y purga periódica de Kafka
# ==============================================================================
# Script de mantenimiento para ejecutar periódicamente (cron/daily) que:
#   1. Comprueba el tamaño del volumen de Kafka en disco
#   2. Fuerza la purga de segmentos antiguos si el disco supera un umbral
#   3. Elimina topics huérfanos o temporales
#   4. Reporta el estado de retención de cada topic
#   5. Genera un log de mantenimiento
#
# Uso:
#   ./kafka-maintenance.sh              # modo normal
#   ./kafka-maintenance.sh --force      # fuerza purga agresiva
#   ./kafka-maintenance.sh --dry-run    # solo reporta, no actúa
#
# Recomendado en cron:
#   0 */6 * * * /path/to/kafka-maintenance.sh >> /var/log/khainet-kafka-maintenance.log 2>&1
# ==============================================================================

set -euo pipefail

# --- Configuración ---
KAFKA_BROKER="${KAFKA_BROKER:-172.25.0.2:9092}"
KAFKA_CONTAINER="khainet-kafka"
KAFKA_VOLUME="khainet-kafka-data"
DISK_THRESHOLD_PERCENT=75    # % de uso de disco para activar purga agresiva
DISK_CRITICAL_PERCENT=90     # % crítico: purga inmediata de todo lo eliminable
LOG_DIR="/var/log/khainet"
LOG_FILE="$LOG_DIR/kafka-maintenance.log"

FORCE_MODE=false
DRY_RUN=false

# --- Parsear argumentos ---
for arg in "$@"; do
    case "$arg" in
        --force)   FORCE_MODE=true ;;
        --dry-run) DRY_RUN=true ;;
    esac
done

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# --- Verificar que Kafka está corriendo ---
if ! docker ps --format '{{.Names}}' | grep -q "^${KAFKA_CONTAINER}$"; then
    log "❌ ERROR: El contenedor $KAFKA_CONTAINER no está corriendo"
    exit 1
fi

log "============================================================"
log " KhaiNet — Mantenimiento de Kafka"
log " Modo: $( $DRY_RUN && echo 'DRY-RUN' || ( $FORCE_MODE && echo 'FORCE' || echo 'NORMAL' ) )"
log "============================================================"

# ==============================================================================
# 1. Comprobar tamaño del volumen de Kafka
# ==============================================================================
log ""
log "--- 1. Tamaño del volumen Kafka ---"

KAFKA_DATA_PATH=$(docker inspect "$KAFKA_CONTAINER" \
    --format '{{ range .Mounts }}{{ if eq .Destination "/var/lib/kafka/data" }}{{ .Source }}{{ end }}{{ end }}' 2>/dev/null || echo "")

if [ -n "$KAFKA_DATA_PATH" ] && [ -d "$KAFKA_DATA_PATH" ]; then
    KAFKA_SIZE=$(du -sh "$KAFKA_DATA_PATH" 2>/dev/null | cut -f1)
    log "  Volumen Kafka ($KAFKA_DATA_PATH): $KAFKA_SIZE"
else
    # Si no podemos acceder al path del host, medir desde dentro del contenedor
    KAFKA_SIZE=$(docker exec "$KAFKA_CONTAINER" du -sh /var/lib/kafka/data 2>/dev/null | cut -f1)
    log "  Volumen Kafka (interno): $KAFKA_SIZE"
fi

# Uso de disco del sistema de archivos donde está Kafka
DISK_USAGE_PERCENT=$(docker exec "$KAFKA_CONTAINER" df -h /var/lib/kafka/data 2>/dev/null \
    | awk 'NR==2 {gsub(/%/, "", $5); print $5}')
DISK_AVAIL=$(docker exec "$KAFKA_CONTAINER" df -h /var/lib/kafka/data 2>/dev/null \
    | awk 'NR==2 {print $4}')
DISK_TOTAL=$(docker exec "$KAFKA_CONTAINER" df -h /var/lib/kafka/data 2>/dev/null \
    | awk 'NR==2 {print $2}')

log "  Disco: $DISK_TOTAL total, $DISK_AVAIL disponible, ${DISK_USAGE_PERCENT}% usado"

# ==============================================================================
# 2. Listar topics y su tamaño aproximado
# ==============================================================================
log ""
log "--- 2. Topics de Kafka ---"

TOPICS_OUTPUT=$(docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server "$KAFKA_BROKER" --list 2>/dev/null)

log "  Topics encontrados:"
echo "$TOPICS_OUTPUT" | while read -r topic; do
    [ -z "$topic" ] && continue

    # Obtener tamaño del topic (offsets y retención)
    CONFIG=$(docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-configs.sh \
        --bootstrap-server "$KAFKA_BROKER" \
        --entity-type topics \
        --entity-name "$topic" \
        --describe 2>/dev/null | grep -E 'retention|cleanup' || echo "  (default)")

    # Contar particiones y offsets
    PARTITIONS=$(docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server "$KAFKA_BROKER" --describe --topic "$topic" 2>/dev/null \
        | grep -c "Partition:" || echo "?")

    log "  • $topic ($PARTITIONS particiones)"
    echo "$CONFIG" | while read -r line; do
        [ -n "$line" ] && log "    $line"
    done
done

# ==============================================================================
# 3. Purgar datos antiguos si es necesario
# ==============================================================================
log ""
log "--- 3. Purga de datos antiguos ---"

NEEDS_PURGE=false

if [ "${DISK_USAGE_PERCENT:-0}" -ge "$DISK_CRITICAL_PERCENT" ]; then
    log "  ⚠️  DISCO CRÍTICO (${DISK_USAGE_PERCENT}% ≥ ${DISK_CRITICAL_PERCENT}%)"
    log "  Activando purga agresiva: reduciendo retención a 1h en topics de sensores"
    NEEDS_PURGE=true
    PURGE_HOURS=1
elif [ "${DISK_USAGE_PERCENT:-0}" -ge "$DISK_THRESHOLD_PERCENT" ]; then
    log "  ⚠️  Disco alto (${DISK_USAGE_PERCENT}% ≥ ${DISK_THRESHOLD_PERCENT}%)"
    log "  Activando purga: reduciendo retención a 6h en topics de sensores"
    NEEDS_PURGE=true
    PURGE_HOURS=6
elif $FORCE_MODE; then
    log "  Modo FORCE: forzando purga con retención estándar"
    NEEDS_PURGE=true
    PURGE_HOURS=12
else
    log "  ✅ Disco OK (${DISK_USAGE_PERCENT}%). No se necesita purga agresiva."
fi

if $NEEDS_PURGE && ! $DRY_RUN; then
    # Topics de sensores (alto volumen) — reducir retención temporalmente
    SENSOR_TOPICS=("zeek-conn" "zeek-dns" "zeek-http" "zeek-ssl" "zeek-files")

    for topic in "${SENSOR_TOPICS[@]}"; do
        log "  → Purgando $topic (retención → ${PURGE_HOURS}h)..."
        docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-configs.sh \
            --bootstrap-server "$KAFKA_BROKER" \
            --entity-type topics \
            --entity-name "$topic" \
            --alter \
            --add-config "retention.ms=$((PURGE_HOURS * 3600 * 1000))" \
            2>/dev/null && log "    ✅ Retención reducida" || log "    ⚠️  No se pudo alterar"

        # Forzar eliminación de segmentos antiguos bajando segment.ms
        docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-configs.sh \
            --bootstrap-server "$KAFKA_BROKER" \
            --entity-type topics \
            --entity-name "$topic" \
            --alter \
            --add-config "segment.ms=60000" \
            2>/dev/null && log "    ✅ Segmentos forzados a 1min" || true
    done

    log ""
    log "  Esperando 90s a que Kafka procese la purga..."
    sleep 90

    # Restaurar retención normal tras la purga
    log "  Restaurando retención normal..."
    for topic in "${SENSOR_TOPICS[@]}"; do
        case "$topic" in
            zeek-conn) HOURS=12; BYTES=2147483648 ;;
            *)         HOURS=24; BYTES=1073741824 ;;
        esac
        docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-configs.sh \
            --bootstrap-server "$KAFKA_BROKER" \
            --entity-type topics \
            --entity-name "$topic" \
            --alter \
            --add-config "retention.ms=$((HOURS * 3600 * 1000)),retention.bytes=${BYTES},segment.ms=3600000" \
            2>/dev/null && log "    ✅ $topic restaurado (${HOURS}h, $(numfmt --to=iec --suffix=B $BYTES))" || true
    done
elif $NEEDS_PURGE && $DRY_RUN; then
    log "  [DRY-RUN] Se purgarían topics de sensores con retención ${PURGE_HOURS}h"
fi

# ==============================================================================
# 4. Eliminar topics huérfanos conocidos (temporales/test)
# ==============================================================================
log ""
log "--- 4. Topics huérfanos ---"

ORPHAN_TOPICS=("test-topic" "temp-" "debug-" "_temporary")
FOUND_ORPHANS=false

for pattern in "${ORPHAN_TOPICS[@]}"; do
    MATCHES=$(echo "$TOPICS_OUTPUT" | grep -i "^${pattern}" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        FOUND_ORPHANS=true
        echo "$MATCHES" | while read -r topic; do
            [ -z "$topic" ] && continue
            log "  → Topic huérfano detectado: $topic"
            if ! $DRY_RUN; then
                docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-topics.sh \
                    --bootstrap-server "$KAFKA_BROKER" \
                    --delete --topic "$topic" 2>/dev/null \
                    && log "    🗑️  Eliminado" || log "    ⚠️  No se pudo eliminar"
            else
                log "    [DRY-RUN] Se eliminaría"
            fi
        done
    fi
done

$FOUND_ORPHANS || log "  ✅ No se encontraron topics huérfanos"

# ==============================================================================
# 5. Reporte final
# ==============================================================================
log ""
log "--- 5. Reporte final ---"

DISK_USAGE_AFTER=$(docker exec "$KAFKA_CONTAINER" df -h /var/lib/kafka/data 2>/dev/null \
    | awk 'NR==2 {gsub(/%/, "", $5); print $5}')
DISK_AVAIL_AFTER=$(docker exec "$KAFKA_CONTAINER" df -h /var/lib/kafka/data 2>/dev/null \
    | awk 'NR==2 {print $4}')

log "  Disco ANTES: ${DISK_USAGE_PERCENT}% usado, ${DISK_AVAIL} disponible"
log "  Disco DESPUÉS: ${DISK_USAGE_AFTER:-?}% usado, ${DISK_AVAIL_AFTER:-?} disponible"

if [ "${DISK_USAGE_AFTER:-${DISK_USAGE_PERCENT}}" -lt "${DISK_USAGE_PERCENT:-100}" ]; then
    log "  ✅ Espacio liberado tras mantenimiento"
else
    log "  ℹ️  No se liberó espacio (los datos estaban dentro de retención)"
fi

log ""
log "============================================================"
log " Mantenimiento completado: $(date '+%Y-%m-%d %H:%M:%S')"
log "============================================================"
log ""
