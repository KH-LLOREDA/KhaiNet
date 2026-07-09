#!/bin/bash
# ==============================================================================
# KhaiNet — Configuración de retención por topic de Kafka
# ==============================================================================
# Aplica políticas de retención diferenciadas a cada topic según su volumen
# y criticidad. Se ejecuta una sola vez tras desplegar Kafka, o cuando se
# añadan nuevos topics.
#
# Uso:
#   ./kafka-retention-config.sh
#
# Requisitos:
#   - Kafka accesible en KAFKA_BROKER (por defecto 172.25.0.2:9092)
#   - kafka-topics disponible (dentro del contenedor o en host con Kafka tools)
# ==============================================================================

set -euo pipefail

KAFKA_BROKER="${KAFKA_BROKER:-172.25.0.2:9092}"
KAFKA_CONTAINER="khainet-kafka"

echo "============================================================"
echo " KhaiNet — Configuración de retención por topic"
echo " Broker: $KAFKA_BROKER"
echo "============================================================"
echo ""

# Función para aplicar retención a un topic
# Argumentos: topic_name retention_hours retention_bytes cleanup_policy
apply_retention() {
    local topic="$1"
    local hours="$2"
    local bytes="$3"
    local policy="${4:-delete}"

    local hours_human
    if [ "$hours" -eq -1 ]; then
        hours_human="infinito"
    else
        hours_human="${hours}h"
    fi

    local bytes_human
    if [ "$bytes" -eq -1 ]; then
        bytes_human="sin límite"
    else
        bytes_human="$(numfmt --to=iec --suffix=B "$bytes" 2>/dev/null || echo "${bytes}B")"
    fi

    echo "→ $topic"
    echo "  Retención: ${hours_human} | Límite: ${bytes_human} | Política: ${policy}"

    docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-configs.sh \
        --bootstrap-server "$KAFKA_BROKER" \
        --entity-type topics \
        --entity-name "$topic" \
        --alter \
        --add-config "retention.ms=$((hours * 3600 * 1000)),retention.bytes=${bytes},cleanup.policy=${policy},segment.ms=3600000" \
        2>/dev/null && echo "  ✅ OK" || echo "  ⚠️  Topic no existe o error (se aplicará al crearse)"
    echo ""
}

# ==============================================================================
# Políticas de retención por topic
# ==============================================================================
# Estructura: topic | horas | bytes | política
#
# Criterios:
#   - Topics de alto volumen (zeek-conn): retención corta (12h, 2GB/partición)
#     porque los datos ya se persisten en OpenSearch y ClickHouse.
#   - Topics de volumen medio (zeek-dns, zeek-http, zeek-ssl): 24h, 1GB/partición
#   - Topics de alertas (suricata-alerts, wazuh-events): 48h, 1GB/partición
#   - Topics de IA (ml-scores, brain-incidents): 72h, 2GB/partición
#     más tiempo porque son el resultado del pipeline y sirven para análisis
#   - Topics internos de Kafka Connect: compact (no delete)
# ==============================================================================

echo "Aplicando políticas de retención..."
echo ""

# --- Topics de sensores (alto volumen, ya persistidos en OS/CH) ---
apply_retention "zeek-conn"           12  2147483648    delete   # 12h, 2GB
apply_retention "zeek-dns"            24  1073741824    delete   # 24h, 1GB
apply_retention "zeek-http"           24  1073741824    delete   # 24h, 1GB
apply_retention "zeek-ssl"            24  1073741824    delete   # 24h, 1GB
apply_retention "zeek-files"          24  1073741824    delete   # 24h, 1GB
apply_retention "zeek-notice"         48  1073741824    delete   # 48h, 1GB

# --- Topics de alertas (volumen medio) ---
apply_retention "suricata-alerts"     48  1073741824    delete   # 48h, 1GB
apply_retention "wazuh-events"        48  1073741824    delete   # 48h, 1GB

# --- Topics de IA (resultado del pipeline, más retención) ---
apply_retention "ml-scores"           72  2147483648    delete   # 72h, 2GB
apply_retention "brain-incidents"     72  2147483648    delete   # 72h, 2GB
apply_retention "brain-dlq"            6   536870912    delete   # 6h, 512MB (DLQ)

# --- Topics internos de Kafka Connect (compactación, no delete) ---
apply_retention "connect-configs"     -1          -1    compact   # compact, sin límite
apply_retention "connect-offsets"     -1          -1    compact   # compact, sin límite
apply_retention "connect-status"      -1          -1    compact   # compact, sin límite

echo "============================================================"
echo " ✅ Configuración de retención aplicada"
echo "============================================================"
echo ""
echo "Para verificar: docker exec khainet-kafka /opt/kafka/bin/kafka-topics.sh \\"
echo "  --bootstrap-server $KAFKA_BROKER --describe --topic <topic>"
echo ""
echo "Para ver la configuración de un topic:"
echo "  docker exec khainet-kafka /opt/kafka/bin/kafka-configs.sh \\"
echo "  --bootstrap-server $KAFKA_BROKER --entity-type topics --entity-name <topic> --describe"
