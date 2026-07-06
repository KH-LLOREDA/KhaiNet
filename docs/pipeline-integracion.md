# Pipeline de Integración con Kafka

## Visión general

El módulo `pipeline/` es el puente entre los sensores de red (simulados) y los módulos de detección y tuning de KhaiNet. Usa Kafka como bus de mensajes desacoplado, permitiendo que cada componente consuma y produzca datos de forma independiente.

```
Sensores (simulados) → Kafka topics → pipeline/ → detection/ → tuning/ → brain/
                         ↑                                              ↓
                    Docker Kafka                                  Kafka (scores)
                    docker02:9092                                 docker02:9092
```

## Infraestructura Kafka

### Despliegue

Kafka está desplegado en **docker02** (172.26.10.98) como contenedores Docker gestionados via Portainer API:

| Contenedor | Imagen | Puerto | Función |
|------------|--------|--------|---------|
| `khainet-kafka` | `apache/kafka:latest` | 9092 | Broker KRaft (sin Zookeeper) |
| `khainet-kafka-ui` | `provectuslabs/kafka-ui:latest` | 8089 | UI web de gestión |

### Configuración Kafka

- **Modo**: KRaft (Kafka Raft, sin Zookeeper) — ahorra ~512 MB RAM
- **Broker**: `172.26.10.98:9092` (accesible desde workspace y red interna)
- **Kafka-UI**: `http://172.26.10.98:8089`
- **Red Docker**: `khainet-network` (172.25.0.0/16)
- **Persistencia**: Almacenamiento efímero (dev). En producción, montar volumen con permisos uid=1000
- **Memoria**: Limitada a 1 GB (configurable)

### Topics

| Topic | Particiones | Productor | Consumer |
|-------|-------------|-----------|----------|
| `zeek-conn` | 3 | sensor_simulator | detection_consumer |
| `zeek-dns` | 3 | sensor_simulator | detection_consumer |
| `zeek-http` | 3 | sensor_simulator | detection_consumer |
| `zeek-ssl` | 3 | sensor_simulator | detection_consumer |
| `suricata-alerts` | 3 | sensor_simulator | tuning_consumer |
| `wazuh-events` | 3 | sensor_simulator | tuning_consumer |
| `ml-scores` | 3 | detection_consumer | tuning_consumer |
| `brain-incidents` | 3 | tuning_consumer | brain/ (futuro) |

## Módulo pipeline/

### Estructura

```
pipeline/
├── __init__.py
├── conftest.py                    # Configuración de pytest (sys.path)
├── pipeline_config.yaml           # Configuración del pipeline
├── src/
│   ├── __init__.py
│   ├── config.py                  # PipelineConfig (Pydantic)
│   ├── models.py                  # Modelos Pydantic del pipeline
│   ├── cross_imports.py           # Bridge para imports detection/tuning
│   ├── kafka_admin.py             # Gestión de topics
│   ├── sensor_simulator.py        # Productor de eventos
│   ├── detection_consumer.py      # Consumer de Zeek → modelos → scores
│   └── tuning_consumer.py         # Consumer de alertas → labels
├── tests/
│   ├── test_kafka_admin.py        # 14 tests
│   ├── test_sensor_simulator.py   # 18 tests
│   ├── test_detection_consumer.py # 16 tests
│   └── test_tuning_consumer.py    # 18 tests
```

### Componentes

#### 1. KafkaAdmin (`kafka_admin.py`)

Gestión de topics de Kafka:
- `create_topics(topics)` — crea topics si no existen
- `list_topics()` — lista todos los topics
- `describe_topic(name)` — particiones, offsets
- `delete_topic(name)` — elimina un topic
- `get_consumer_lag(group_id, topic)` — lag del consumer group
- `ensure_all_topics()` — crea los 8 topics por defecto

#### 2. SensorSimulator (`sensor_simulator.py`)

Productor de eventos que simula sensores reales:
- Genera eventos Zeek (conn, dns, http, ssl) usando `detection/synthetic_data.py`
- Genera alertas Suricata y eventos Wazuh sintéticos
- Inyecta anomalías configurables: port_scan, data_exfil, c2_beacon, dns_tunneling
- Controla eventos/segundo y ratio de anomalías
- Ejecutable standalone: `python -m pipeline.src.sensor_simulator`

#### 3. DetectionConsumer (`detection_consumer.py`)

Consumer que procesa eventos Zeek con los modelos de detección:
- Suscribe a `zeek-conn`, `zeek-dns`, `zeek-http`, `zeek-ssl`
- Acumula eventos en lotes (batch de 20) para mejor rendimiento
- Pasa lotes al `DetectionOrchestrator.detect()` (IF + AE + HMM)
- Produce scores individuales a `ml-scores`
- Thread asíncrono, no bloquea el dashboard
- Ejecutable standalone: `python -m pipeline.src.detection_consumer`

#### 4. TuningConsumer (`tuning_consumer.py`)

Consumer que procesa alertas y genera etiquetas:
- Suscribe a `suricata-alerts`, `wazuh-events`, `ml-scores`
- Convierte alertas Suricata/Wazuh en etiquetas via `label_sources/`
- Combina etiquetas con `WeakSupervisor` (weak supervision tipo Snorkel)
- Selecciona eventos inciertos con `ActiveLearningSelector`
- Acepta feedback del analista via `submit_analyst_feedback()`
- Produce incidentes consensuados a `brain-incidents`
- Ejecutable standalone: `python -m pipeline.src.tuning_consumer`

### Cross-imports (`cross_imports.py`)

Los módulos `detection/`, `tuning/` y `pipeline/` todos usan `src` como nombre de package. La solución son context managers que intercambian `sys.path` y `sys.modules` temporalmente:

```python
with detection_context():
    from src.orchestrator import DetectionOrchestrator  # detection/src/
# Al salir, pipeline's src se restaura
```

## Dashboard integrado

El dashboard (`demo/server.py`) funciona en modo híbrido:

1. **Modo memoria** (rápido): El `DemoEngine` procesa eventos en memoria para visualización instantánea
2. **Modo Kafka** (paralelo): El `KafkaBridge` replica los mismos eventos a Kafka para que el pipeline real los procese

### Panel de Kafka en el dashboard

El dashboard muestra un panel colapsable con:
- Estado de conexión (verde/rojo)
- Broker: 172.26.10.98:9092
- Eventos enviados a Kafka
- Grid de 8 topics con indicador de actividad
- Link a Kafka-UI (http://172.26.10.98:8089)

### Endpoints API

| Endpoint | Descripción |
|----------|-------------|
| `GET /api/kafka/status` | Estado de Kafka (conexión, eventos, topics) |
| `GET /api/kafka/topics` | Lista de topics con metadata |
| `GET /api/stats` | Stats generales (incluye `kafka` section) |

## Tests

```
cd /workspace && python -m pytest pipeline/tests/ -v
======================= 66 passed, 226 warnings in 1.89s =======================
```

- 66 tests, 0 fallos
- Todos usan mocks (no requieren Kafka real ni detection/tuning real)
- Cobertura: kafka_admin, sensor_simulator, detection_consumer, tuning_consumer

## Configuración

`pipeline/pipeline_config.yaml`:

```yaml
kafka:
  broker: "172.26.10.98:9092"
  client_id: "khainet-pipeline"

topics:
  zeek-conn:
    partitions: 3
    replication: 1
  # ... (8 topics total)

sensor:
  rate: 10  # eventos/segundo
  anomaly_ratio: 0.05
  anomaly_types: [port_scan, data_exfil, c2_beacon, dns_tunneling]

detection:
  consumer_group: "detection-consumer"
  batch_size: 20
  auto_offset_reset: "latest"

tuning:
  consumer_group: "tuning-consumer"
  temporal_window_seconds: 60
  auto_offset_reset: "latest"
```

## Transición a infraestructura real

Cuando se desplieguen sensores reales (Zeek, Suricata, Wazuh), el cambio es mínimo:

1. **Sensores → Kafka**: Reemplazar `sensor_simulator.py` por Filebeat/Logstash leyendo logs reales
2. **Detection consumer**: Sin cambios — ya consume de Kafka
3. **Tuning consumer**: Sin cambios — ya consume de Kafka
4. **Dashboard**: Sin cambios — ya muestra estado de Kafka

El pipeline está diseñado para ser 100% reutilizable con infraestructura real.

## Commits

- `74a04f9` — `feat(pipeline): Kafka bus module connecting sensors → detection → tuning`
- `43429c8` — `feat(demo): integrate Kafka bridge into dashboard with real-time panel`
