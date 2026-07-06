# KhaiNet — Kafka Connect con plugins Elasticsearch (→OpenSearch) y ClickHouse
# Extiende la imagen oficial de Confluent e instala los sink connectors
#
# OpenSearch compatibility: el Elasticsearch connector de Confluent es compatible
# con OpenSearch porque este mantiene la REST API de Elasticsearch 7.x.
# Se apunta la URL al OpenSearch y funciona sin cambios.
#
# Build: docker build -t khainet-kafka-connect:latest .
# Run:   ver docker-compose-kafka-connect.yml

FROM confluentinc/cp-kafka-connect:7.7.3

# Instalar plugins via Confluent Hub
# Elasticsearch Sink Connector (compatible con OpenSearch REST API)
RUN confluent-hub install --no-prompt confluentinc/kafka-connect-elasticsearch:latest
# ClickHouse Kafka Connector
RUN confluent-hub install --no-prompt clickhouse/clickhouse-kafka-connect:latest

# Los plugins se instalan en /usr/share/confluent-hub-components/
# confluent-hub actualiza automáticamente el plugin path en connect-distributed.properties
ENV CONNECT_PLUGIN_PATH=/usr/share/java/kafka-connect/plugins,/usr/share/confluent-hub-components
