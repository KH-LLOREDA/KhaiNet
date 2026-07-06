#!/usr/bin/env bash
# KhaiNet — Kafka Connect deployment script
# Despliega Kafka Connect en docker02 via Portainer Docker API
# Crea la imagen custom con plugins, arranca el container y registra los connectors
#
# Uso: ./deploy.sh
# Requisitos: JWT de Portainer en /tmp/portainer_jwt.txt

set -euo pipefail

PORTAINER="http://172.26.10.98:9000/api"
ENDPOINT_ID=3
JWT=$(python3 -c "import json; print(json.load(open('/tmp/portainer_jwt.txt'))['jwt'])")
AUTH="-H \"Authorization: Bearer $JWT\""

echo "=== KhaiNet — Kafka Connect Deployment ==="
echo ""

# ────────────────────────────────────────────────────────────────
# 1. Build custom image with plugins
# ────────────────────────────────────────────────────────────────
echo "--- Step 1: Building custom Kafka Connect image ---"

# Create a tar with the Dockerfile for the Docker build API
DOCKERFILE_DIR="$(dirname "$0")"
tar -cf - -C "$DOCKERFILE_DIR" Dockerfile | \
  curl -s -X POST "$PORTAINER/endpoints/$ENDPOINT_ID/docker/build?t=khainet-kafka-connect:latest" \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/x-tar" \
    --data-binary @-

echo ""
echo "Image build initiated"

# ────────────────────────────────────────────────────────────────
# 2. Create and start container
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Step 2: Creating Kafka Connect container ---"

# Check if container already exists
EXISTING=$(curl -s "$PORTAINER/endpoints/$ENDPOINT_ID/docker/containers/json?all=1&filters=%7B%22name%22%3A%5B%22khainet-kafka-connect%22%5D%7D" \
  -H "Authorization: Bearer $JWT" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0]['Id'] if data else '')")

if [ -n "$EXISTING" ]; then
  echo "Container already exists (ID: $EXISTING), removing..."
  curl -s -X DELETE "$PORTAINER/endpoints/$ENDPOINT_ID/docker/containers/$EXISTING?force=true" \
    -H "Authorization: Bearer $JWT"
  echo "Removed."
fi

# Create container via Docker API
CONTAINER_RESP=$(cat <<'EOF' | curl -s -X POST "$PORTAINER/endpoints/$ENDPOINT_ID/docker/containers/create?name=khainet-kafka-connect" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d @-
{
  "Image": "khainet-kafka-connect:latest",
  "Hostname": "khainet-kafka-connect",
  "Env": [
    "CONNECT_BOOTSTRAP_SERVERS=172.25.0.2:9092",
    "CONNECT_REST_ADVERTISED_HOST_NAME=172.26.10.98",
    "CONNECT_REST_PORT=8083",
    "CONNECT_GROUP_ID=khainet-connect",
    "CONNECT_CONFIG_STORAGE_TOPIC=connect-configs",
    "CONNECT_OFFSET_STORAGE_TOPIC=connect-offsets",
    "CONNECT_STATUS_STORAGE_TOPIC=connect-status",
    "CONNECT_CONFIG_STORAGE_REPLICATION_FACTOR=1",
    "CONNECT_OFFSET_STORAGE_REPLICATION_FACTOR=1",
    "CONNECT_STATUS_STORAGE_REPLICATION_FACTOR=1",
    "CONNECT_KEY_CONVERTER=org.apache.kafka.connect.json.JsonConverter",
    "CONNECT_VALUE_CONVERTER=org.apache.kafka.connect.json.JsonConverter",
    "CONNECT_KEY_CONVERTER_SCHEMAS_ENABLE=false",
    "CONNECT_VALUE_CONVERTER_SCHEMAS_ENABLE=false",
    "CONNECT_INTERNAL_KEY_CONVERTER=org.apache.kafka.connect.json.JsonConverter",
    "CONNECT_INTERNAL_VALUE_CONVERTER=org.apache.kafka.connect.json.JsonConverter",
    "CONNECT_PLUGIN_PATH=/usr/share/java/kafka-connect/plugins,/usr/share/confluent-hub-components",
    "CONNECT_LOG4J_LOGGERS=org.apache.zookeeper=ERROR,org.I0Itec.zkclient=ERROR,org.reflections=ERROR"
  ],
  "ExposedPorts": { "8083/tcp": {} },
  "HostConfig": {
    "PortBindings": { "8083/tcp": [{ "HostPort": "8083" }] },
    "NetworkMode": "khainet-network",
    "RestartPolicy": { "Name": "unless-stopped" }
  }
}
EOF
)

CONTAINER_ID=$(echo "$CONTAINER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Id',''))")
if [ -z "$CONTAINER_ID" ]; then
  echo "❌ Failed to create container: $CONTAINER_RESP"
  exit 1
fi
echo "✅ Container created: $CONTAINER_ID"

# Start container
curl -s -X POST "$PORTAINER/endpoints/$ENDPOINT_ID/docker/containers/$CONTAINER_ID/start" \
  -H "Authorization: Bearer $JWT"
echo "✅ Container started"

# ────────────────────────────────────────────────────────────────
# 3. Wait for Kafka Connect REST API to be ready
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Step 3: Waiting for Kafka Connect REST API ---"
for i in $(seq 1 60); do
  if curl -s --connect-timeout 2 http://172.26.10.98:8083/ >/dev/null 2>&1; then
    echo "✅ Kafka Connect REST API is ready (attempt $i)"
    break
  fi
  echo "  Waiting... ($i/60)"
  sleep 5
done

# ────────────────────────────────────────────────────────────────
# 4. Register connectors
# ────────────────────────────────────────────────────────────────
echo ""
echo "--- Step 4: Registering connectors ---"

CONNECTORS_DIR="$(dirname "$0")/connectors"
for conn_file in "$CONNECTORS_DIR"/*.json; do
  conn_name=$(basename "$conn_file" .json)
  echo "  Registering: $conn_name"
  curl -s -X POST http://172.26.10.98:8083/connectors \
    -H "Content-Type: application/json" \
    -d @"$conn_file" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'    ✅ {d.get(\"name\",\"?\")}')" 2>/dev/null || \
  echo "    ⚠️  Failed to register $conn_name"
done

echo ""
echo "=== Deployment complete ==="
echo "Kafka Connect REST API: http://172.26.10.98:8083"
echo "Connectors: http://172.26.10.98:8083/connectors"
