# KhaiNet — Kafka Connect Sinks (Kafka → OpenSearch + ClickHouse)

## Resumen

Sistema de sinks que automatically indexa eventos de Kafka en OpenSearch (búsqueda/dashboards) y ClickHouse (analytics/ML). Cierra el círculo de la infraestructura: `Sensores → Kafka → Sinks → OpenSearch + ClickHouse`.

## Arquitectura

```
                                   ┌─────────────────────┐
                                   │   OpenSearch (9200)  │
                                   │   Logs + alertas     │
                                   │   Búsqueda/dashboards│
                                   └────────▲────────────┘
                                            │
                                   ┌────────┴────────────┐
                                   │   Logstash (7.16.3)  │
                                   │   Kafka → OpenSearch │
                                   │   172.25.0.8         │
                                   └────────▲────────────┘
                                            │
Sensores → Kafka (9092) ────────────────────┤
                                   ┌────────┴────────────┐
                                   │  Kafka Connect (7.7) │
                                   │  ClickHouse sink     │
                                   │  172.25.0.7:8083     │
                                   └────────▲────────────┘
                                            │
                                   ┌────────┴────────────┐
                                   │  ClickHouse (8123)   │
                                   │  Analytics/ML        │
                                   │  Features/scores     │
                                   └─────────────────────┘
```

## Componentes desplegados en docker02 (172.26.10.98)

### Kafka Connect (172.25.0.7)
- **Imagen**: `khainet-kafka-connect:latest` (custom, basada en `confluentinc/cp-kafka-connect:7.7.3`)
- **Plugins**: 
  - ClickHouse Kafka Connector v1.3.9 (`clickhouse/clickhouse-kafka-connect`)
  - Elasticsearch Sink Connector v15.1.2 (`confluentinc/kafka-connect-elasticsearch`) — instalado pero no usado (incompatible con OpenSearch 2.x)
- **REST API**: `http://172.26.10.98:8083`
- **Connectors**: 5 ClickHouse sink connectors (todos RUNNING)

### Logstash (172.25.0.8)
- **Imagen**: `opensearchproject/logstash-oss-with-opensearch-output-plugin:7.16.3`
- **Función**: Kafka → OpenSearch sink
- **Por qué Logstash en lugar de Kafka Connect**: El Elasticsearch connector de Confluent (v15.1.2) no es compatible con OpenSearch 2.x porque verifica la versión de Elasticsearch y rechaza OpenSearch (versión 2.16.0 < 6). Logstash tiene un plugin nativo de OpenSearch output.
- **Config**: `logstash/kafka-to-opensearch.conf` (en volumen `khainet-logstash-config`)
- **Topics consumidos**: zeek-conn, zeek-dns, zeek-http, zeek-ssl, suricata-alerts, wazuh-events, brain-incidents

## Routing de topics

### OpenSearch (vía Logstash) — todos los topics
| Topic | Índice OpenSearch | Uso |
|-------|-------------------|-----|
| zeek-conn | zeek-conn | Logs de conexión |
| zeek-dns | zeek-dns | Eventos DNS |
| zeek-http | zeek-http | Eventos HTTP |
| zeek-ssl | zeek-ssl | Eventos SSL/TLS |
| suricata-alerts | suricata-alerts | Alertas Suricata |
| wazuh-events | wazuh-events | Eventos Wazuh |
| brain-incidents | brain-incidents | Incidentes Brain |

### ClickHouse (vía Kafka Connect) — features + ML
| Topic | Tabla ClickHouse | Uso |
|-------|-----------------|-----|
| zeek-conn | zeek-conn | Features de flujos |
| zeek-dns | zeek-dns | Features DNS |
| zeek-http | zeek-http | Features HTTP |
| zeek-ssl | zeek-ssl | Features SSL |
| ml-scores | ml-scores | Scores de anomalía ML |

## Topics internos de Kafka Connect
- `connect-configs` (1 partition, compacted) — configuración de connectors
- `connect-offsets` (25 partitions, compacted) — offsets de consumers
- `connect-status` (5 partitions, compacted) — estado de connectors

## Notas técnicas

### OpenSearch: mapping dinámico
Los index templates originales definían `src_ip` y `dst_ip` como tipo `ip`, pero los eventos del pipeline tienen IPs seudonimizadas (hashes hexadecimales). Se eliminaron los index templates restrictivos y se usa mapping dinámico: OpenSearch infiere los tipos automáticamente al recibir los documentos.

### ClickHouse: tablas con nombre de topic
El ClickHouse connector v1.3.9 busca tablas con el mismo nombre que el topic de Kafka. El parámetro `topic2TableMap` no funciona en esta versión. Se crearon tablas con el nombre del topic (`zeek-conn`, `zeek-dns`, etc.) con tipos compatibles con los datos reales del pipeline (String para IPs, Array para arrays, Nullable para campos opcionales).

### ClickHouse: tablas originales vs topic-named
Las tablas originales (`network_flows`, `dns_events`, etc.) se mantienen para referencia futura. Las tablas topic-named (`zeek-conn`, `zeek-dns`, etc.) son las que recibe datos del connector. En producción, se pueden crear vistas materializadas o renombrar las tablas.

## Archivos
- `Dockerfile` — imagen custom de Kafka Connect con plugins
- `docker-compose-kafka-connect.yml` — compose para Kafka Connect
- `docker-compose-logstash.yml` — compose para Logstash
- `logstash/kafka-to-opensearch.conf` — config de Logstash
- `connectors/` — JSON configs de los 7 connectors (5 ClickHouse + 2 OpenSearch)
- `deploy.sh` — script de despliegue automatizado
