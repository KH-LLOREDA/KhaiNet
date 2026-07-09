#!/bin/bash
# ============================================================
# KhaiNet — OpenSearch ISM (Index State Management) Setup
# ============================================================
# Crea/actualiza las políticas de retención de índices en OpenSearch
# y las aplica a los índices existentes.
#
# Políticas (fase desarrollo — 30 días):
#   - khainet-alerts-30d: wazuh-*, brain-* (alertas e incidentes)
#   - khainet-logs-30d:   zeek-*, suricata-* (logs de red)
#
# En producción, aumentar a 90d (logs) / 180d (alertas) según requisitos.
#
# Uso: ./opensearch-ism-setup.sh [opensearch_url] [user] [password]
# ============================================================

set -euo pipefail

OS_URL="${1:-http://172.25.0.5:9200}"
OS_USER="${2:-admin}"
OS_PASS="${3:-Khainet2025Secure}"

echo "=== KhaiNet — OpenSearch ISM Setup ==="
echo "  URL: $OS_URL"
echo "  User: $OS_USER"
echo ""

# Verificar conexión
if ! curl -s -u "$OS_USER:$OS_PASS" "$OS_URL/_cluster/health" >/dev/null 2>&1; then
    echo "ERROR: No se puede conectar a OpenSearch en $OS_URL"
    exit 1
fi

# ---------------------------------------------------------------
# Política: Alertas (brain-*, wazuh-*) — 30 días
# ---------------------------------------------------------------
echo "--- Creando política khainet-alerts-30d ---"
# Eliminar si existe (ignorar error si no existe)
curl -s -X DELETE -u "$OS_USER:$OS_PASS" "$OS_URL/_plugins/_ism/policies/khainet-alerts-30d" >/dev/null 2>&1 || true

curl -s -X PUT -u "$OS_USER:$OS_PASS" \
    -H "Content-Type: application/json" \
    "$OS_URL/_plugins/_ism/policies/khainet-alerts-30d" \
    -d '{
    "policy": {
        "description": "Retencion 30 dias para alertas (Wazuh, Brain) - fase desarrollo",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": { "min_index_age": "30d" }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "retry": { "count": 3, "backoff": "exponential", "delay": "1m" },
                        "delete": {}
                    }
                ],
                "transitions": []
            }
        ],
        "ism_template": [
            {
                "index_patterns": ["wazuh-*", "brain-*"],
                "priority": 100
            }
        ]
    }
}'
echo ""

# ---------------------------------------------------------------
# Política: Logs de red (zeek-*, suricata-*) — 30 días
# ---------------------------------------------------------------
echo "--- Creando política khainet-logs-30d ---"
curl -s -X DELETE -u "$OS_USER:$OS_PASS" "$OS_URL/_plugins/_ism/policies/khainet-logs-30d" >/dev/null 2>&1 || true

curl -s -X PUT -u "$OS_USER:$OS_PASS" \
    -H "Content-Type: application/json" \
    "$OS_URL/_plugins/_ism/policies/khainet-logs-30d" \
    -d '{
    "policy": {
        "description": "Retencion 30 dias para logs de red (Zeek, Suricata) - fase desarrollo",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": { "min_index_age": "30d" }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "retry": { "count": 3, "backoff": "exponential", "delay": "1m" },
                        "delete": {}
                    }
                ],
                "transitions": []
            }
        ],
        "ism_template": [
            {
                "index_patterns": ["zeek-*", "suricata-*"],
                "priority": 100
            }
        ]
    }
}'
echo ""

# ---------------------------------------------------------------
# Aplicar políticas a índices existentes
# ---------------------------------------------------------------
echo "--- Aplicando políticas a índices existentes ---"

# Obtener lista de índices que coinciden con los patrones
ALERT_INDICES=$(curl -s -u "$OS_USER:$OS_PASS" "$OS_URL/_cat/indices/wazuh-*,brain-*?h=index" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
LOG_INDICES=$(curl -s -u "$OS_USER:$OS_PASS" "$OS_URL/_cat/indices/zeek-*,suricata-*?h=index" 2>/dev/null | tr '\n' ',' | sed 's/,$//')

if [ -n "$ALERT_INDICES" ]; then
    echo "  Alertas: $ALERT_INDICES"
    # Remover policy anterior si la tiene
    curl -s -X POST -u "$OS_USER:$OS_PASS" "$OS_URL/_plugins/_ism/remove/$ALERT_INDICES" >/dev/null 2>&1 || true
    sleep 2
    curl -s -X POST -u "$OS_USER:$OS_PASS" \
        -H "Content-Type: application/json" \
        "$OS_URL/_plugins/_ism/add/$ALERT_INDICES" \
        -d '{"policy_id": "khainet-alerts-30d"}'
    echo ""
else
    echo "  No hay índices de alertas existentes"
fi

if [ -n "$LOG_INDICES" ]; then
    echo "  Logs: $LOG_INDICES"
    curl -s -X POST -u "$OS_USER:$OS_PASS" "$OS_URL/_plugins/_ism/remove/$LOG_INDICES" >/dev/null 2>&1 || true
    sleep 2
    curl -s -X POST -u "$OS_USER:$OS_PASS" \
        -H "Content-Type: application/json" \
        "$OS_URL/_plugins/_ism/add/$LOG_INDICES" \
        -d '{"policy_id": "khainet-logs-30d"}'
    echo ""
else
    echo "  No hay índices de logs existentes"
fi

# ---------------------------------------------------------------
# Configurar replicas=0 (single-node, no necesita réplicas)
# ---------------------------------------------------------------
echo "--- Configurando replicas=0 (single-node) ---"
curl -s -X PUT -u "$OS_USER:$OS_PASS" \
    -H "Content-Type: application/json" \
    "$OS_URL/_all/_settings" \
    -d '{"index": {"number_of_replicas": 0}}'
echo ""

# ---------------------------------------------------------------
# Eliminar índice roto si existe (bug de Logstash)
# ---------------------------------------------------------------
BROKEN_IDX=$(echo "%{[@metadata][index_name]}" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))" 2>/dev/null || echo "")
if [ -n "$BROKEN_IDX" ]; then
    echo "--- Eliminando índice roto si existe ---"
    curl -s -X DELETE -u "$OS_USER:$OS_PASS" "$OS_URL/$BROKEN_IDX" 2>/dev/null || true
    echo ""
fi

# ---------------------------------------------------------------
# Verificar estado final
# ---------------------------------------------------------------
echo "=== Verificación ==="
echo "--- Políticas ISM ---"
curl -s -u "$OS_USER:$OS_PASS" "$OS_URL/_plugins/_ism/policies?pretty" 2>/dev/null | grep -E '"_id"|"description"|"min_index_age"' || echo "  (sin políticas)"
echo ""
echo "--- Cluster health ---"
curl -s -u "$OS_USER:$OS_PASS" "$OS_URL/_cluster/health?pretty" 2>/dev/null | grep -E '"status"|"number_of_nodes"|"active_shards"'
echo ""
echo "=== ISM Setup completado ==="
