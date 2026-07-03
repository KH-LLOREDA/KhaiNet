# KhaiNet Brain — Correlation and Reasoning Engine

> **Component:** Brain (Capa 5 — Correlación y Razonamiento)
> **Proyecto:** KhaiNet · NDR open-source con IA propia
> **Versión:** 1.0 · Fecha: 2026-07-03

Brain es el **cerebro de razonamiento** de KhaiNet. No detecta amenazas en tiempo
real; opera como capa de correlación sobre **alertas pre-filtradas** producidas por
los modelos de anomalías (Isolation Forest, Autoencoders, HMM), Suricata (firmas)
y Wazuh (HIDS).

## Funciones principales

1. **Correlación multi-evento** — agrupa alertas dispersas en incidentes coherentes
2. **Enriquecimiento** — combina asset inventory, GeoIP, threat intel (MISP) e historial
3. **Scoring de severidad** — asigna score 0–100 con contexto
4. **Reducción de falsos positivos** — descarta alertas que con contexto son benignas
5. **Explicabilidad (XAI)** — narrativa en lenguaje natural de cada incidente
6. **Priorización** — ordena incidentes para que el SOC atienda primero los críticos
7. **Salida a SOAR** — envía sugerencias de respuesta a Shuffle

## Arquitectura

```
Kafka topics (entrada)                    Pipeline Brain                    Salidas
┌──────────────────────┐         ┌──────────────────────────┐     ┌─────────────────┐
│ ml-scores            │         │  consumer.py             │     │ Kafka           │
│ suricata-alerts      │────────▶│  (asyncio, 3 topics)     │     │ brain-incidents │
│ wazuh-events         │         │         │                │     └────────┬────────┘
└──────────────────────┘         │         ▼                │              │
                                 │  correlator.py           │              ▼
                                 │  (deque + Redis sessions)│     ┌─────────────────┐
                                 │         │                │     │ Shuffle SOAR    │
                                 │         ▼                │     │ (webhook REST)  │
                                 │  enricher.py             │     └─────────────────┘
                                 │  (asset, GeoIP, MISP,    │
                                 │   ClickHouse historial)  │
                                 │         │                │
                                 │         ▼                │
                                 │  scorer.py               │
                                 │  (scoring compuesto)     │
                                 │         │                │
                                 │         ▼                │
                                 │  brain_client.py         │
                                 │  (LLM con circuit breaker│
                                 │   + fallback graceful)   │
                                 │         │                │
                                 │         ▼                │
                                 │  xai.py                  │
                                 │  (explicabilidad)        │
                                 │         │                │
                                 │         ▼                │
                                 │  producer.py +           │
                                 │  shuffle_client.py       │
                                 └──────────────────────────┘
```

## Estructura del proyecto

```
brain/
├── config/
│   ├── settings.yaml              # Configuración general
│   └── prompts/
│       ├── correlation.txt        # Prompt de correlación + razonamiento
│       └── xai_fallback.txt       # Prompt simplificado para reproceso
├── src/
│   ├── __init__.py
│   ├── main.py                    # Entry point: orquesta pipeline asíncrono
│   ├── consumer.py                # Kafka consumer asíncrono (3 topics)
│   ├── models.py                  # Pydantic models: Alert, Incident, etc.
│   ├── correlator.py              # Pipeline de correlación: deque + Redis sessions
│   ├── enricher.py                # Enriquecimiento paralelo (4 fuentes)
│   ├── scorer.py                  # Scoring de severidad compuesto (0–100)
│   ├── brain_client.py            # Cliente LLM (httpx + tenacity + circuit breaker)
│   ├── xai.py                     # Explicabilidad: narrativa del incidente
│   ├── shuffle_client.py          # Cliente Shuffle SOAR (webhook REST)
│   ├── producer.py                # Kafka producer (brain-incidents)
│   ├── state_manager.py           # Gestión de sesiones en Redis
│   ├── schema_validator.py        # Validación Pydantic + detección de alucinaciones
│   ├── dlq_handler.py             # Dead Letter Queue para irrecuperables
│   ├── feedback_loop.py           # Ingesta de respuestas de analistas/Shuffle
│   └── metrics.py                 # Métricas Prometheus + reporte semanal
├── schemas/
│   ├── alert_schema.json          # JSON Schema del contrato de entrada
│   └── incident_schema.json       # JSON Schema del contrato de salida
├── tests/
│   ├── conftest.py                # Fixtures compartidas (mocks)
│   ├── test_consumer.py
│   ├── test_correlator.py
│   ├── test_enricher.py
│   ├── test_scorer.py
│   ├── test_brain_client.py
│   ├── test_xai.py
│   ├── test_shuffle_client.py
│   ├── test_state_manager.py
│   ├── test_schema_validator.py
│   └── test_integration.py        # Test end-to-end con mocks
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Requisitos

- Python 3.12+
- Kafka (confluent-kafka)
- Redis
- LLM endpoint (Brain/KH7 compatible con OpenAI API)
- Opcional: MISP, ClickHouse, OpenSearch, MaxMind GeoLite2

## Instalación

```bash
# Crear entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

## Ejecutar el servicio

### Con Docker Compose (desarrollo)

```bash
# Configurar variables de entorno
export MISP_API_KEY="your-misp-key"
export SHUFFLE_API_KEY="your-shuffle-key"

# Iniciar infraestructura + Brain
docker-compose up -d
```

### Sin Docker (desarrollo local)

```bash
# Asegurar que Kafka, Redis y el LLM están accesibles
# Editar config/settings.yaml con las URLs correctas

# Ejecutar
python -m src.main
```

### Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka bootstrap servers | `localhost:9092` |
| `LLM_BASE_URL` | URL del LLM | `http://localhost:8080` |
| `REDIS_URL` | URL de Redis | `redis://localhost:6379/0` |
| `MISP_URL` | URL de MISP | `http://localhost:80` |
| `MISP_API_KEY` | API key de MISP | — |
| `CLICKHOUSE_URL` | URL de ClickHouse | `http://localhost:8123` |
| `OPENSEARCH_URL` | URL de OpenSearch | `http://localhost:9200` |
| `SHUFFLE_URL` | URL de Shuffle | `http://localhost:3001` |
| `SHUFFLE_API_KEY` | API key de Shuffle | — |
| `LOG_LEVEL` | Nivel de logging | `INFO` |
| `BRAIN_CONFIG_PATH` | Ruta al config YAML | `config/settings.yaml` |

## Ejecutar tests

```bash
# Todos los tests (sin infraestructura real — todos los mocks)
pytest

# Con verbose
pytest -v

# Solo tests de un módulo
pytest tests/test_correlator.py

# Con coverage
pytest --cov=src --cov-report=term-missing
```

Los tests no requieren infraestructura real. Todos los clientes externos
(Kafka, LLM, Redis, MISP, ClickHouse, OpenSearch, Shuffle) están mockeados.

## Pipeline de procesamiento

1. **Consumer** lee alertas de 3 topics Kafka → `asyncio.Queue`
2. **Correlator** agrupa alertas por entidad (src_ip) usando:
   - Ventana deslizante de 5 min (`collections.deque`)
   - Sessionization de 30 min (Redis con TTL)
   - Detección de patrones multi-stage (scan→exfil, C2, lateral, DNS tunneling)
3. **Enricher** enriquece en paralelo con 4 fuentes (`asyncio.gather`)
4. **Scorer** calcula severidad 0-100 con fórmula compuesta
5. **Brain LLM Client** llama al LLM con circuit breaker + semantic cache
6. **XAI Builder** construye la narrativa del incidente
7. **Producer** envía incidentes a Kafka (`brain-incidents`)
8. **Shuffle Client** envía incidentes a Shuffle SOAR vía webhook

### Fallback graceful

Si el LLM falla (timeout, circuit breaker abierto, alucinación):
- Se usa scoring matemático sin XAI
- El incidente se etiqueta `needs_xai_reprocess`
- `xai_available = false`, `explanation = null`

### Dead Letter Queue

Mensajes irrecuperables (schema inválido, errores de procesamiento) se envían
al topic `brain-dlq` con el mensaje original, error y contexto.

## Scoring

```
severity = (
    model_severity     * 0.40 +
    asset_criticality  * 0.25 +
    threat_intel_match * 0.15 +
    historical_deviation * 0.10 +
    correlation_strength * 0.10
)
```

Bonus no lineal para casos extremos:
- threat_intel=100 + asset_criticality≥80 → +20%
- correlation=100 + model_severity≥70 → +10%

| Score | Label | Acción SOAR |
|-------|-------|-------------|
| 80–100 | `critical` | Aislamiento + notificación + ticket |
| 60–79 | `high` | Notificación + ticket |
| 40–59 | `medium` | Ticket + monitorización |
| 0–39 | `low` | Logging |

## Métricas Prometheus

| Métrica | Tipo | Descripción |
|---------|------|-------------|
| `brain_alerts_received_total` | counter | Alertas recibidas por source |
| `brain_incidents_produced_total` | counter | Incidentes por severity_label |
| `brain_llm_calls_total` | counter | Llamadas al LLM (success/failure/timeout) |
| `brain_llm_latency_seconds` | histogram | Latencia del LLM |
| `brain_circuit_breaker_state` | gauge | Estado del circuit breaker |
| `brain_enrichment_failures_total` | counter | Fallos de enriquecimiento por fuente |
| `brain_dlq_messages_total` | counter | Mensajes enviados a DLQ |
| `brain_processing_time_seconds` | histogram | Tiempo de procesamiento por incidente |
| `brain_xai_availability_ratio` | gauge | Ratio de incidentes con XAI vs fallback |

## GDPR

- **IPs seudonimizadas**: Brain recibe IPs como hash SHA-256+sal, no realiza re-identificación
- **No persistencia innecesaria**: Los datos se persisten en OpenSearch con retención 365 días
- **Minimización**: Brain recibe alertas pre-filtradas, no tráfico bruto
- **Audit logging**: Toda acción se registra con timestamp via structlog
- **Art. 22 GDPR**: Las acciones destructivas requieren aprobación humana (`auto_execute=false`)

## Especificación técnica

Ver `docs/brain-component-spec.md` para la especificación completa (947 líneas).

---

*Mantenido por el equipo KhaiNet (Grupo Khlloreda / KH7)*
