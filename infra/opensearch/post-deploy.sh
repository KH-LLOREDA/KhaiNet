#!/usr/bin/env bash
# KhaiNet — OpenSearch post-deploy configuration
# Ejecutar después de que OpenSearch esté healthy
# Configura: index templates, ISM policies, ingest pipeline de seudonimización

set -euo pipefail

OS_HOST="${1:-http://172.26.10.98:9200}"
OS_USER="${2:-admin}"
OS_PASS="${3:-Khainet2025!Secure}"

AUTH="-u ${OS_USER}:${OS_PASS} -k --silent"

echo "=== KhaiNet OpenSearch post-deploy ==="
echo "Host: ${OS_HOST}"

# ────────────────────────────────────────────────────────────────
# 1. Verificar cluster health
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Cluster health ---"
curl ${AUTH} -X GET "${OS_HOST}/_cluster/health" | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 2. Ingest pipeline: seudonimización de IPs (GDPR compliance)
#    Hash SHA-256 con sal. En producción, la sal va en el Keystore.
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando ingest pipeline: khainet-ip-pseudonymization ---"
curl ${AUTH} -X PUT "${OS_HOST}/_ingest/pipeline/khainet-ip-pseudonymization" \
  -H "Content-Type: application/json" -d '
{
  "description": "Seudonimiza IPs con hash SHA-256 + sal (GDPR compliance)",
  "processors": [
    {
      "script": {
        "lang": "painless",
        "source": """
          String salt = "khainet-dev-salt-change-in-prod";
          String hashIp(String ip) {
            if (ip == null || ip.isEmpty()) return ip;
            def md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest(ip.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
              sb.append(String.format("%02x", b & 0xff));
            }
            return "sha256:" + sb.toString().substring(0, 16);
          }
          // Pseudonymize IP fields commonly found in Zeek/Suricata/Wazuh logs
          if (ctx.src_ip != null) ctx.src_ip_pseudo = hashIp(ctx.src_ip);
          if (ctx.dst_ip != null) ctx.dst_ip_pseudo = hashIp(ctx.dst_ip);
          if (ctx.source?.ip != null) ctx.source.ip_pseudo = hashIp(ctx.source.ip);
          if (ctx.destination?.ip != null) ctx.destination.ip_pseudo = hashIp(ctx.destination.ip);
        """
      }
    }
  ]
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 3. ISM Policy: retención 180 días para logs de red
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando ISM policy: khainet-logs-180d ---"
curl ${AUTH} -X PUT "${OS_HOST}/_plugins/_ism/policies/khainet-logs-180d" \
  -H "Content-Type: application/json" -d '
{
  "policy": {
    "description": "Retención 180 días para logs de red (Zeek, Suricata)",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "180d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ],
    "ism_template": {
      "index_patterns": ["zeek-*", "suricata-*"],
      "priority": 100
    }
  }
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 4. ISM Policy: retención 365 días para alertas
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando ISM policy: khainet-alerts-365d ---"
curl ${AUTH} -X PUT "${OS_HOST}/_plugins/_ism/policies/khainet-alerts-365d" \
  -H "Content-Type: application/json" -d '
{
  "policy": {
    "description": "Retención 365 días para alertas (Suricata, Wazuh, Brain)",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "365d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ],
    "ism_template": {
      "index_patterns": ["wazuh-*", "brain-*"],
      "priority": 100
    }
  }
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 5. Index template: Zeek logs
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando index template: zeek-logs ---"
curl ${AUTH} -X PUT "${OS_HOST}/_index_template/zeek-logs" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["zeek-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "5s",
      "index.plugins.index_state_management.rollover_alias": "zeek-logs"
    },
    "mappings": {
      "properties": {
        "@timestamp":   { "type": "date" },
        "ts":           { "type": "date" },
        "src_ip":       { "type": "ip" },
        "dst_ip":       { "type": "ip" },
        "src_port":     { "type": "integer" },
        "dst_port":     { "type": "integer" },
        "proto":        { "type": "keyword" },
        "service":      { "type": "keyword" },
        "duration":     { "type": "double" },
        "orig_bytes":   { "type": "long" },
        "resp_bytes":   { "type": "long" },
        "conn_state":   { "type": "keyword" },
        "sensor_id":    { "type": "keyword" },
        "src_ip_pseudo":  { "type": "keyword" },
        "dst_ip_pseudo":  { "type": "keyword" }
      }
    }
  },
  "priority": 200
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 6. Index template: Suricata alerts
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando index template: suricata-alerts ---"
curl ${AUTH} -X PUT "${OS_HOST}/_index_template/suricata-alerts" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["suricata-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp":   { "type": "date" },
        "timestamp":    { "type": "date" },
        "src_ip":       { "type": "ip" },
        "dst_ip":       { "type": "ip" },
        "src_port":     { "type": "integer" },
        "dst_port":     { "type": "integer" },
        "alert": {
          "properties": {
            "signature":  { "type": "text" },
            "category":   { "type": "keyword" },
            "severity":   { "type": "integer" },
            "action":     { "type": "keyword" }
          }
        },
        "sensor_id":    { "type": "keyword" },
        "src_ip_pseudo":  { "type": "keyword" },
        "dst_ip_pseudo":  { "type": "keyword" }
      }
    }
  },
  "priority": 200
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 7. Index template: Wazuh alerts
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando index template: wazuh-alerts ---"
curl ${AUTH} -X PUT "${OS_HOST}/_index_template/wazuh-alerts" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["wazuh-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp":     { "type": "date" },
        "timestamp":      { "type": "date" },
        "rule": {
          "properties": {
            "level":      { "type": "integer" },
            "description":{ "type": "text" },
            "groups":     { "type": "keyword" },
            "id":         { "type": "keyword" }
          }
        },
        "agent": {
          "properties": {
            "id":         { "type": "keyword" },
            "name":       { "type": "keyword" },
            "ip":         { "type": "ip" }
          }
        },
        "manager": {
          "properties": {
            "name":       { "type": "keyword" }
          }
        },
        "location":       { "type": "keyword" },
        "full_log":       { "type": "text" },
        "src_ip_pseudo":  { "type": "keyword" },
        "dst_ip_pseudo":  { "type": "keyword" }
      }
    }
  },
  "priority": 200
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 8. Index template: Brain incidents
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Creando index template: brain-incidents ---"
curl ${AUTH} -X PUT "${OS_HOST}/_index_template/brain-incidents" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["brain-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp":     { "type": "date" },
        "incident_id":    { "type": "keyword" },
        "severity":       { "type": "integer" },
        "confidence":     { "type": "double" },
        "title":          { "type": "text" },
        "description":    { "type": "text" },
        "correlations":   { "type": "object", "enabled": false },
        "recommended_actions": { "type": "object", "enabled": false },
        "src_ip":         { "type": "ip" },
        "dst_ip":         { "type": "ip" },
        "src_ip_pseudo":  { "type": "keyword" },
        "dst_ip_pseudo":  { "type": "keyword" }
      }
    }
  },
  "priority": 200
}
' | python3 -m json.tool

# ────────────────────────────────────────────────────────────────
# 9. Verificar configuración
# ────────────────────────────────────────────────────────────────
echo ""
echo "=== Verificación ==="
echo "--- Pipelines ---"
curl ${AUTH} -X GET "${OS_HOST}/_ingest/pipeline/khainet-ip-pseudonymization" | python3 -c "import sys,json; d=json.load(sys.stdin); print('✅ Pipeline creado' if 'khainet-ip-pseudonymization' in d else '❌ Pipeline no encontrado')"

echo "--- ISM Policies ---"
curl ${AUTH} -X GET "${OS_HOST}/_plugins/_ism/policies" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'✅ {k}') for k in d.get('policies',{})]"

echo "--- Index Templates ---"
curl ${AUTH} -X GET "${OS_HOST}/_index_template" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'✅ {t[\"name\"]}') for t in d.get('index_templates',[])]"

echo ""
echo "=== Post-deploy completado ==="
