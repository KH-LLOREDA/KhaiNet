# KhaiNet — Especificación técnica del componente Brain

> **Componente:** Brain (Capa 5 — Correlación y Razonamiento)
> **Proyecto:** KhaiNet · NDR open-source con IA propia
> **Versión:** 1.0 · Fecha: 2026-07-03
> **Issue:** Integración de Brain como capa de correlación y razonamiento
> **Vinculado a:** [Arquitectura KhaiNet](darktrace-alternativa-software-libre.md) — Secciones 2, 5 y 6, Fase 4

---

## 1. Resumen

Brain es el **cerebro de razonamiento** de KhaiNet. No detecta amenazas en tiempo real;
opera como capa de correlación sobre **alertas pre-filtradas** producidas por los modelos
de anomalías (Isolation Forest, Autoencoders, HMM), Suricata (firmas) y Wazuh (HIDS).

**Funciones principales:**
1. **Correlación multi-evento** — agrupa alertas dispersas en incidentes coherentes
2. **Enriquecimiento** — combina asset inventory, GeoIP, threat intel (MISP) e historial
3. **Scoring de severidad** — asigna score 0–100 con contexto
4. **Reducción de falsos positivos** — descarta alertas que con contexto son benignas
5. **Explicabilidad (XAI)** — narrativa en lenguaje natural de cada incidente
6. **Priorización** — ordena incidentes para que el SOC atienda primero los críticos
7. **Salida a SOAR** — envía sugerencias de respuesta a Shuffle

---

## 2. Arquitectura del componente

### 2.1 Visión general

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

### 2.2 Principios de diseño

1. **Asíncrono** — `asyncio` para maximizar concurrencia; el consumer no bloquea esperando al LLM
2. **Desacoplado** — el consumer y la inferencia del LLM están separados por una cola interna (`asyncio.Queue`)
3. **Resiliente** — circuit breaker en el cliente LLM, fallback graceful si el LLM falla, Dead Letter Queue para irrecuperables
4. **Validado** — Pydantic para validación de schemas en entrada y salida del LLM
5. **Observable** — métricas, logs estructurados, tracing de cada paso del pipeline
6. **GDPR-compliant** — IPs seudonimizadas, no persistencia de datos personales más allá del ciclo

### 2.3 Estructura de módulos

```
brain/
├── config/
│   ├── settings.yaml              # Configuración general (Kafka, LLM, Redis, timeouts)
│   └── prompts/
│       ├── correlation.txt        # Prompt de correlación + razonamiento
│       └── xai_fallback.txt       # Prompt simplificado para reproceso
├── src/
│   ├── __init__.py
│   ├── main.py                    # Entry point: orquesta pipeline asíncrono
│   ├── consumer.py                # Kafka consumer asíncrono (3 topics)
│   ├── models.py                  # Pydantic models: Alert, Incident, EnrichmentData
│   ├── correlator.py              # Pipeline de correlación: deque + Redis sessions
│   ├── enricher.py                # Enriquecimiento paralelo (asset, GeoIP, MISP, historial)
│   ├── scorer.py                  # Scoring de severidad compuesto (0–100)
│   ├── brain_client.py            # Cliente LLM (httpx + tenacity + circuit breaker)
│   ├── xai.py                     # Explicabilidad: narrativa del incidente
│   ├── shuffle_client.py          # Cliente Shuffle SOAR (webhook REST)
│   ├── producer.py                # Kafka producer (brain-incidents)
│   ├── state_manager.py           # Gestión de sesiones en Redis (sessionization)
│   ├── schema_validator.py        # Validación Pydantic pre/post LLM
│   ├── dlq_handler.py             # Dead Letter Queue para irrecuperables
│   ├── feedback_loop.py           # Ingesta de respuestas de analistas/Shuffle
│   └── metrics.py                 # Métricas semanales KhaiNet vs Darktrace
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
├── docs/
│   └── brain-component.md         # Documentación técnica (este archivo)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 3. Contrato de entrada — Alert

### 3.1 JSON Schema

Las alertas pre-filtradas que Brain recibe de Kafka deben cumplir este contrato:

```json
{
  "alert_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-07-03T10:15:30.000Z",
  "source": "ml-isolation-forest",
  "source_type": "anomaly",
  "severity_raw": 75,
  "confidence": 0.85,
  "src_ip": "a1b2c3d4e5f6...",
  "dst_ip": "f7e8d9c0b1a2...",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "tcp",
  "service": "ssl",
  "bytes": 1048576,
  "packets": 1024,
  "duration": 30.5,
  "ml_model": "isolation-forest",
  "ml_score": 0.92,
  "ml_features": {
    "bytes_out": 900000,
    "bytes_in": 148576,
    "destinations_unique": 1,
    "dns_queries": 0,
    "hour_of_day": 10,
    "day_of_week": 4
  },
  "rule_id": null,
  "rule_message": null,
  "event_type": "exfiltration",
  "tags": ["high-bytes-out", "rare-destination"],
  "raw_event": {}
}
```

### 3.2 Campos obligatorios vs opcionales

| Campo | Tipo | Obligatorio | Descripción |
|-------|------|-------------|-------------|
| `alert_id` | UUID | ✅ | Identificador único de la alerta |
| `timestamp` | ISO-8601 | ✅ | Momento del evento |
| `source` | string | ✅ | Origen: `ml-isolation-forest`, `ml-autoencoder`, `ml-hmm`, `suricata`, `wazuh` |
| `source_type` | enum | ✅ | `anomaly`, `signature`, `host` |
| `severity_raw` | int 0–100 | ✅ | Severidad inicial del detector |
| `confidence` | float 0–1 | ✅ | Confianza del detector |
| `src_ip` | string | ✅ | IP origen (seudonimizada: hash SHA-256+sal) |
| `dst_ip` | string | ✅ | IP destino (seudonimizada) |
| `protocol` | string | ✅ | `tcp`, `udp`, `icmp` |
| `event_type` | enum | ✅ | `scan`, `c2_beaconing`, `lateral_movement`, `exfiltration`, `dns_tunneling`, `anomaly` |
| `src_port` | int | ❌ | Puerto origen |
| `dst_port` | int | ❌ | Puerto destino |
| `service` | string | ❌ | Servicio L7: `http`, `dns`, `ssl`, `smb`, `rdp`, `ssh`, etc. |
| `bytes` | int | ❌ | Bytes totales |
| `packets` | int | ❌ | Paquetes totales |
| `duration` | float | ❌ | Duración en segundos |
| `ml_model` | string | ❌ | Modelo ML que generó la alerta |
| `ml_score` | float | ❌ | Score del modelo (0–1) |
| `ml_features` | object | ❌ | Features usadas por el modelo |
| `rule_id` | string | ❌ | SID de Suricata o rule ID de Wazuh |
| `rule_message` | string | ❌ | Mensaje de la regla |
| `tags` | string[] | ❌ | Tags adicionales |
| `raw_event` | object | ❌ | Evento crudo (para auditoría) |

### 3.3 Validación

- Pydantic model `Alert` valida cada mensaje al entrar
- Si una alerta no valida → se envía a DLQ (`brain-dlq`) con el error
- Campos opcionales se rellenan con `None` o valores por defecto

---

## 4. Contrato de salida — Incident

### 4.1 JSON Schema

```json
{
  "incident_id": "660e8400-e29b-41d4-a716-446655440001",
  "created_at": "2026-07-03T10:20:00.000Z",
  "status": "new",
  "severity": 82,
  "severity_label": "critical",
  "confidence": 0.88,
  "title": "Posible exfiltración de datos desde servidor crítico hacia IP externa no categorizada",
  "description": "El servidor SRV-DB-01 (activo crítico) ha realizado una transferencia de 900KB hacia una IP externa no vista previamente en el baseline. La conexión ocurrió fuera del horario habitual de actividad del servidor. Se detectaron 3 alertas correlacionadas: anomalía de volumen (Isolation Forest), conexión a destino raro (Autoencoder) y transición de estado anómala (HMM).",
  "explanation": "Brain correlaciona tres señales independientes que convergen en el mismo activo y ventana temporal: (1) Isolation Forest detecta un volumen saliente atípico (p99 del baseline), (2) Autoencoder detecta que el destino no forma parte del patrón normal de SRV-DB-01, (3) HMM detecta una transición de estado 'normal→exfil'. La combinación de las tres señales aumenta la confianza significativamente. El activo es un servidor de base de datos clasificado como crítico, lo que eleva el impacto potencial.",
  "correlation_reason": "Las 3 alertas comparten la misma IP origen (SRV-DB-01), ocurren dentro de una ventana de 5 minutos, y el patrón volumen+destino+raro+transición de estado es consistente con exfiltración.",
  "false_positive_assessment": "Descartado como FP: el volumen saliente supera el p99 del baseline histórico de 30 días. El destino no aparece en la lista de destinos legítimos del servidor. No hay ventana de mantenimiento programada. Sin embargo, se recomienda verificar con el administrador del servidor si hay un backup o replicación programada no documentada.",
  "recommended_actions": [
    {
      "action": "notify_soc",
      "target": "soc-team",
      "priority": "immediate",
      "auto_execute": true,
      "justification": "Severidad crítica en activo crítico requiere notificación inmediata"
    },
    {
      "action": "create_ticket",
      "target": "thehive",
      "priority": "immediate",
      "auto_execute": true,
      "justification": "Crear caso en TheHive para tracking"
    },
    {
      "action": "isolate_host",
      "target": "SRV-DB-01",
      "priority": "high",
      "auto_execute": false,
      "justification": "Aislamiento requiere aprobación humana por ser servidor crítico en producción"
    },
    {
      "action": "block_ip",
      "target": "IP externa destino",
      "priority": "high",
      "auto_execute": false,
      "justification": "Bloquear IP de destino sospechosa en perimeter"
    }
  ],
  "alerts": [
    {"alert_id": "...", "source": "ml-isolation-forest", "event_type": "exfiltration", "severity_raw": 75},
    {"alert_id": "...", "source": "ml-autoencoder", "event_type": "anomaly", "severity_raw": 68},
    {"alert_id": "...", "source": "ml-hmm", "event_type": "exfiltration", "severity_raw": 80}
  ],
  "entities": {
    "src_hosts": ["SRV-DB-01"],
    "dst_hosts": ["unknown-external"],
    "src_ips": ["a1b2c3d4e5f6..."],
    "dst_ips": ["f7e8d9c0b1a2..."]
  },
  "enrichment": {
    "asset_info": {
      "hostname": "SRV-DB-01",
      "type": "server",
      "criticality": 5,
      "os": "Linux",
      "services": ["postgresql", "ssh"],
      "owner": "DBA Team"
    },
    "geoip": {
      "dst_country": "RU",
      "dst_city": "Unknown",
      "dst_asn": "AS12345",
      "dst_asn_org": "Unknown ISP"
    },
    "threat_intel": {
      "dst_ip_malicious": true,
      "dst_ip_tags": ["c2-server", "botnet"],
      "source": "MISP"
    },
    "historical_context": {
      "first_seen_dst": "2026-07-03T10:15:00Z",
      "baseline_bytes_out_p99": 50000,
      "actual_bytes_out": 900000,
      "deviation_factor": 18.0
    }
  },
  "timeline": [
    {"timestamp": "2026-07-03T10:15:30Z", "event": "Isolation Forest: anomalía de volumen saliente (score 0.92)"},
    {"timestamp": "2026-07-03T10:17:00Z", "event": "Autoencoder: destino fuera del patrón normal (error reconstrucción > p99)"},
    {"timestamp": "2026-07-03T10:18:45Z", "event": "HMM: transición de estado normal→exfil detectada"},
    {"timestamp": "2026-07-03T10:20:00Z", "event": "Brain: incidente correlacionado y publicado"}
  ],
  "metrics": {
    "alert_count": 3,
    "time_span_seconds": 210,
    "unique_sources": 3,
    "unique_destinations": 1
  },
  "xai_available": true,
  "llm_model": "brain-kh7-v1",
  "llm_latency_ms": 3200
}
```

### 4.2 Campos del incidente

| Campo | Tipo | Obligatorio | Descripción |
|-------|------|-------------|-------------|
| `incident_id` | UUID | ✅ | Identificador único del incidente |
| `created_at` | ISO-8601 | ✅ | Momento de creación |
| `status` | enum | ✅ | `new`, `investigating`, `contained`, `resolved` |
| `severity` | int 0–100 | ✅ | Score de severidad calculado |
| `severity_label` | enum | ✅ | `critical` (80–100), `high` (60–79), `medium` (40–59), `low` (0–39) |
| `confidence` | float 0–1 | ✅ | Confianza de Brain en la correlación |
| `title` | string | ✅ | Resumen conciso del incidente |
| `description` | string | ✅ | Narrativa de qué ocurrió (orden temporal) |
| `explanation` | string | ✅* | Razonamiento de Brain (*null si fallback sin LLM) |
| `correlation_reason` | string | ✅ | Por qué las alertas se agruparon |
| `false_positive_assessment` | string | ✅ | Evaluación de si es FP |
| `recommended_actions` | Action[] | ✅ | Acciones sugeridas con justificación |
| `alerts` | Alert[] | ✅ | Alertas que componen el incidente |
| `entities` | object | ✅ | Hosts e IPs implicados |
| `enrichment` | object | ✅ | Datos de enriquecimiento |
| `timeline` | TimelineEntry[] | ✅ | Eventos en orden temporal |
| `metrics` | object | ✅ | Métricas del incidente |
| `xai_available` | bool | ✅ | Si hay explicación del LLM (false si fallback) |
| `llm_model` | string | ❌ | Modelo usado (null si fallback) |
| `llm_latency_ms` | int | ❌ | Latencia de la llamada al LLM |

---

## 5. Pipeline de correlación

### 5.1 Ventana híbrida (deslizante + sessionization)

**Dos niveles de correlación:**

1. **Ventana deslizante corta (5 min)** — para detección inmediata de ataques rápidos
   - Implementación: `collections.deque` por entidad (src_ip)
   - En cada inserción, elimina eventos con `timestamp < now - 5min` (O(1))
   - Cuando se acumulan ≥2 alertas para una entidad, se dispara correlación

2. **Sessionization por entidad (timeout 30 min)** — para campañas lentas/APTs
   - Implementación: Redis con TTL de 30 min por sesión
   - Una sesión se mantiene activa mientras lleguen alertas para la misma entidad
   - Si no hay nuevas alertas en 30 min, la sesión se cierra y se evalúa para correlación
   - Permite correlacionar eventos distantes en el tiempo (scan a las 10:00 → exfil a las 10:25)

### 5.2 Algoritmo de agrupación

```python
def group_alerts(alerts: list[Alert], sessions: SessionManager) -> list[AlertGroup]:
    groups = []
    for alert in alerts:
        # 1. Actualizar sesión por entidad (src_ip)
        session = sessions.update(alert.src_ip, alert)

        # 2. Ventana deslizante: alertas en los últimos 5 min para esta entidad
        recent = session.get_recent(window_seconds=300)

        # 3. Si hay ≥2 alertas recientes, formar grupo candidato
        if len(recent) >= 2:
            group = AlertGroup(
                alerts=recent,
                entity=alert.src_ip,
                reason="shared_source_proximity"
            )
            groups.append(group)

        # 4. Detección de patrones multi-stage
        pattern = detect_attack_pattern(session.all_alerts)
        if pattern:
            group = AlertGroup(
                alerts=pattern.alerts,
                entity=alert.src_ip,
                reason=f"attack_pattern_{pattern.name}"
            )
            groups.append(group)

    return deduplicate(groups)
```

### 5.3 Patrones de ataque detectables

| Patrón | Secuencia | Detección |
|--------|-----------|-----------|
| **Campaña de exfiltración** | scan → connection → high-bytes-out | event_type sequence + volume threshold |
| **C2 beaconing** | periodic-connection → dns-anomaly → ssl-anomaly | temporal regularity + DNS+SSL anomalies |
| **Lateral movement** | scan → new-internal-connection → smb/rdp-anomaly | internal dst + service change |
| **DNS tunneling** | dns-high-entropy → dns-volume-anomaly → dns-txt-frequent | DNS features correlation |

### 5.4 Filtrado pre-LLM

Antes de enviar al LLM, se filtran grupos triviales para ahorrar coste:
- 1 alerta de severidad < 40 sin contexto agravante → descartar (publicar como alerta simple)
- Grupos ya procesados idénticos (semantic cache) → reusar resultado anterior
- Grupos que matchean reglas de FP conocidas (backups nocturnos, scans autorizados) → descartar

---

## 6. Enriquecimiento

### 6.1 Fuentes de enriquecimiento (paralelo, asyncio.gather)

| Fuente | Implementación | Datos aportados |
|--------|---------------|-----------------|
| **Asset inventory** | OpenSearch query o DB interna | hostname, tipo (server/workstation/IoT), criticality (1–5), OS, servicios, owner |
| **GeoIP** | MaxMind GeoLite2 (local, sin API externa) | país, ciudad, ASN, organización |
| **Threat intel** | MISP API (PyMISP) | IOCs, tags, reputación de IP/dominio |
| **Historial** | ClickHouse query | baseline del host, first-seen del destino, desviación estadística |

### 6.2 Estructura de enriquecimiento

```python
async def enrich(alert_group: AlertGroup) -> EnrichmentData:
    """Enriquece un grupo de alertas en paralelo."""
    src_ips = group.get_src_ips()
    dst_ips = group.get_dst_ips()

    # Las 4 fuentes en paralelo
    asset_info, geoip, threat_intel, historical = await asyncio.gather(
        asset_lookup(src_ips),
        geoip_lookup(dst_ips),
        threat_intel_lookup(src_ips + dst_ips),
        historical_lookup(src_ips, dst_ips),
        return_exceptions=True  # Si una fuente falla, continuar con las demás
    )

    return EnrichmentData(
        asset_info=asset_info if not isinstance(asset_info, Exception) else {},
        geoip=geoip if not isinstance(geoip, Exception) else {},
        threat_intel=threat_intel if not isinstance(threat_intel, Exception) else {},
        historical_context=historical if not isinstance(historical, Exception) else {}
    )
```

### 6.3 Tolerancia a fallos

- Cada fuente de enriquecimiento es independiente
- Si una fuente falla (timeout, conexión rechazada), se continúa con las demás
- El enriquecimiento parcial se marca en el incidente (`enrichment.partial = true`)
- Se registra en métricas qué fuente falló

---

## 7. Scoring de severidad

### 7.1 Fórmula compuesta (0–100)

```
severity = (
    model_severity     * 0.40 +   # Severidad media de las alertas de entrada
    asset_criticality  * 0.25 +   # Criticidad del activo afectado (1-5 → 0-100)
    threat_intel_match * 0.15 +   # Coincidencia con IOCs conocidos
    historical_deviation * 0.10 + # Desviación del comportamiento histórico
    correlation_strength * 0.10   # Número y coherencia de alertas correlacionadas
)
```

### 7.2 Componentes

| Componente | Rango | Cálculo |
|-----------|-------|---------|
| `model_severity` | 0–100 | Media ponderada de `severity_raw` de las alertas (peso por `confidence`) |
| `asset_criticality` | 0–100 | `criticality_level * 20` (1=20, 5=100); si no hay info, 40 (medio por defecto) |
| `threat_intel_match` | 0–100 | 100 si hay match malicioso en MISP; 50 si hay tags sospechosos; 0 si no hay match |
| `historical_deviation` | 0–100 | `min(100, deviation_factor * 10)` donde deviation_factor = actual / baseline_p99 |
| `correlation_strength` | 0–100 | `min(100, alert_count * 25)` (1 alerta=25, 2=50, 3=75, 4+=100) |

### 7.3 Escalado no lineal (bonus)

Para casos extremos, se aplica un bonus que escala no linealmente:

```python
# Si threat_intel_match = 100 (C2 conocido) Y asset_criticality >= 4
if threat_intel_match >= 100 and asset_criticality >= 80:
    severity = min(100, severity * 1.2)  # +20% bonus

# Si correlation_strength = 100 (≥4 alertas) Y model_severity >= 70
if correlation_strength >= 100 and model_severity >= 70:
    severity = min(100, severity * 1.1)  # +10% bonus
```

### 7.4 Etiquetas de severidad

| Score | Label | Acción SOAR |
|-------|-------|-------------|
| 80–100 | `critical` | Aislamiento + notificación + ticket (auto, con guardrails) |
| 60–79 | `high` | Notificación + ticket (auto) |
| 40–59 | `medium` | Ticket + monitorización (auto) |
| 0–39 | `low` | Logging (auto) |

> **Nota:** Los pesos son fijos para el MVP y shadow mode. Se ajustarán con regresión
> lineal al final de los 12 meses, comparando con las etiquetas de Darktrace.

---

## 8. Cliente LLM (Brain/KH7)

### 8.1 Arquitectura del cliente

```python
class BrainLLMClient:
    """Cliente para el LLM Brain/KH7 con resiliencia."""

    def __init__(self, config):
        self.http_client = httpx.AsyncClient(timeout=30.0)
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            half_open_max_calls=3
        )
        self.semantic_cache = SemanticCache(redis, ttl=300)  # 5 min cache

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(min=1, max=10),
        retry=tenacity.retry_if_exception_type((httpx.TimeoutException, httpx.ConnectionError))
    )
    async def correlate(self, alert_group: dict, enrichment: dict) -> dict:
        # 1. Check semantic cache
        cache_key = hash_group(alert_group)
        cached = await self.semantic_cache.get(cache_key)
        if cached:
            return cached

        # 2. Circuit breaker
        if not self.circuit_breaker.can_call():
            raise CircuitBreakerOpenError("LLM circuit breaker open")

        # 3. Build prompt
        prompt = self.build_prompt(alert_group, enrichment)

        # 4. Call LLM
        try:
            response = await self.http_client.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,  # Baja temperatura para consistencia
                    "max_tokens": 2000,
                    "response_format": {"type": "json_object"}  # Forzar JSON
                }
            )
            result = response.json()

            # 5. Validate output against schema
            validated = self.schema_validator.validate_incident(result)

            # 6. Cache result
            await self.semantic_cache.set(cache_key, validated)

            self.circuit_breaker.record_success()
            return validated

        except (httpx.TimeoutException, httpx.ConnectionError, SchemaValidationError) as e:
            self.circuit_breaker.record_failure()
            raise
```

### 8.2 Prompt del sistema

```
You are Brain, the correlation and reasoning engine of KhaiNet, an open-source NDR platform.
Your role is to analyze pre-filtered security alerts and produce correlated incidents.

You receive a JSON object containing:
- A group of related alerts (with ML scores, event types, network metadata)
- Enrichment data (asset info, GeoIP, threat intel, historical context)

You must return a JSON object with:
- title: concise summary of the incident
- description: narrative of what happened (chronological order)
- explanation: reasoning of why this is a real incident
- correlation_reason: why these alerts were grouped together
- false_positive_assessment: why this is NOT a false positive (or why it is)
- severity_adjustment: suggested adjustment to the calculated severity (-20 to +20)
- confidence: your confidence in this assessment (0.0 to 1.0)
- recommended_actions: list of actions with justification

Rules:
- Base your analysis ONLY on the provided data. Do not invent IPs, hosts, or events.
- If data is insufficient, set confidence low and note it in the explanation.
- If the pattern matches known legitimate behavior (backups, maintenance), assess as FP.
- Recommended actions must include justification.
- auto_execute should be false for destructive actions (isolation, blocking).
- Respond in Spanish.
- Return valid JSON only.
```

### 8.3 Fallback graceful

Si el LLM falla (timeout, circuit breaker abierto, alucinación detectada):

```python
async def process_with_fallback(group, enrichment, scorer):
    try:
        # Intentar con LLM
        llm_result = await brain_client.correlate(group, enrichment)
        incident = build_incident(group, enrichment, llm_result, scorer)
        incident.xai_available = True
        return incident

    except (CircuitBreakerOpenError, httpx.TimeoutException, SchemaValidationError):
        # Fallback: scoring matemático sin XAI
        severity = scorer.calculate(group, enrichment)
        incident = build_incident_fallback(group, enrichment, severity, scorer)
        incident.xai_available = False
        incident.explanation = None
        incident.description = f"Incidente correlacionado por scoring automático (LLM no disponible). {len(group.alerts)} alertas, severidad {severity}."
        incident.tags.append("needs_xai_reprocess")
        return incident
```

### 8.4 Detección de alucinaciones

```python
def validate_llm_output(llm_result: dict, input_group: dict) -> bool:
    """Valida que el LLM no haya inventado datos."""
    # 1. IPs mencionadas en la salida deben estar en la entrada
    input_ips = extract_ips(input_group)
    output_ips = extract_ips(llm_result)
    if output_ips - input_ips:
        raise SchemaValidationError(f"LLM inventó IPs: {output_ips - input_ips}")

    # 2. Hosts mencionados deben estar en la entrada o en el enriquecimiento
    # 3. Alertas referenciadas deben existir en la entrada
    # 4. Schema validation con Pydantic
    return True
```

---

## 9. Explicabilidad (XAI)

### 9.1 Estructura de la explicación

Brain genera 6 componentes de explicabilidad:

1. **Title** — Resumen conciso (máx 100 chars)
   - Ej: "Posible exfiltración desde SRV-DB-01 hacia IP externa no categorizada"

2. **Description** — Narrativa cronológica de qué ocurrió
   - Orden temporal de eventos, datos cuantitativos, contexto del activo

3. **Explanation** — Razonamiento de por qué es un incidente real
   - Qué señales convergen, por qué aumentan la confianza, qué impacto potencial

4. **Correlation reason** — Por qué las alertas se agruparon
   - Entidades compartidas, proximidad temporal, patrón de ataque detectado

5. **False positive assessment** — Por qué NO es FP (o por qué sí)
   - Qué datos descartan FP, qué verificar manualmente como excepción

6. **Recommended actions** — Acciones con justificación
   - Cada acción incluye por qué se recomienda y si es auto-ejecutable

### 9.2 Trazabilidad

Cada incidente incluye:
- `timeline[]`: eventos en orden temporal con descripción
- `alerts[]`: alertas originales que componen el incidente
- `enrichment{}`: datos de contexto usados
- `llm_model`: modelo usado para la explicación
- `llm_latency_ms`: tiempo de inferencia

---

## 10. Integración con Shuffle (SOAR)

### 10.1 Webhook

Brain envía incidentes a Shuffle vía webhook REST:

```
POST {SHUFFLE_URL}/api/v1/workflows/brain-incident/executions
Content-Type: application/json
Authorization: Bearer {SHUFFLE_API_KEY}

Body: {incident JSON completo}
```

### 10.2 Mapeo de acciones

| `severity_label` | Playbook Shuffle | Acciones automáticas |
|------------------|-----------------|---------------------|
| `critical` | `brain-critical-response` | Notificación SOC (Teams/email) + ticket TheHive + recolección de evidencias. Aislamiento/bloqueo requieren aprobación humana. |
| `high` | `brain-high-response` | Notificación SOC + ticket TheHive + enriquecimiento Cortex |
| `medium` | `brain-medium-response` | Ticket TheHive + monitorización |
| `low` | `brain-low-response` | Logging en OpenSearch |

### 10.3 Guardrails

- `auto_execute: false` en acciones destructivas (aislamiento, bloqueo) → Shuffle no las ejecuta sin aprobación humana
- Toda acción se audita y es reversible
- Shuffle devuelve feedback a Brain (vía `feedback_loop.py`) sobre el resultado de cada playbook

---

## 11. Métricas semanales — KhaiNet vs Darktrace

### 11.1 KPIs comparativos

| KPI | Definición | Objetivo |
|-----|-----------|----------|
| **Cobertura** | % de incidentes de Darktrace que KhaiNet también detecta | > 90% |
| **Precisión** | % de alertas de KhaiNet que son verdaderos positivos | > 85% |
| **Ventaja** | Nº de incidentes que KhaiNet detecta y Darktrace no | ≥ 0 |
| **Latencia (MTTD)** | Tiempo medio captura → alerta accionable | Comparable (±30%) |
| **Falsos positivos** | % de alertas que el SOC descarta como benignas | < 15% |
| **Reducción por Brain** | % de alertas que Brain agrupó/redujo vs alertas crudas | > 50% |
| **XAI availability** | % de incidentes con explicación del LLM (vs fallback) | > 95% |
| **LLM latency p95** | Percentil 95 de latencia del LLM | < 5s |

### 11.2 Script de métricas

`metrics.py` genera un reporte semanal en markdown:

```markdown
# Reporte semanal KhaiNet vs Darktrace — Semana del 2026-06-26 al 2026-07-02

## Resumen ejecutivo
- KhaiNet detectó 145 incidentes vs 152 de Darktrace
- Cobertura: 95.4% (145/152)
- Precisión: 87.6% (127/145 TP)
- Ventaja: 8 incidentes detectados solo por KhaiNet
- MTTD KhaiNet: 8.2 min vs Darktrace 7.1 min (+15.5%)

## Detalle por categoría
[tabla con breakdown por event_type]

## Brain performance
- Alertas recibidas: 1,847
- Incidentes producidos: 145 (reducción 92.1%)
- XAI disponible: 98.6% (2 incidentes en fallback)
- LLM latency p50: 2.8s, p95: 4.1s, p99: 6.2s

## Falsos positivos
- FP rate: 12.4% (18/145)
- Categorías más frecuentes de FP: [lista]

## Recomendaciones
- [sugerencias de tuning basadas en los datos]
```

### 11.3 Dashboard Grafana

- Panel de cobertura comparativa (KhaiNet vs Darktrace) — gauge chart
- Panel de precisión — time series
- Panel de Brain performance — alertas vs incidentes, XAI availability, LLM latency
- Panel de FP por categoría — bar chart

---

## 12. Resiliencia y observabilidad

### 12.1 Dead Letter Queue (DLQ)

- Topic Kafka `brain-dlq` para alertas/incidentes que fallan irrecuperablemente
- Cada mensaje en DLQ incluye: mensaje original, error, timestamp, componente que falló
- Proceso de revisión manual de DLQ por el SOC

### 12.2 Circuit breaker

- Estado: `closed` (normal), `open` (LLM caído, fallback activo), `half_open` (probando recuperación)
- Umbral: 5 fallos consecutivos → `open`
- Recovery: 60s → `half_open`, 3 llamadas exitosas → `closed`

### 12.3 Métricas internas (Prometheus)

| Métrica | Tipo | Descripción |
|---------|------|-------------|
| `brain_alerts_received_total` | counter | Alertas recibidas por source |
| `brain_incidents_produced_total` | counter | Incidentes producidos por severity_label |
| `brain_llm_calls_total` | counter | Llamadas al LLM (success/failure/timeout) |
| `brain_llm_latency_seconds` | histogram | Latencia del LLM |
| `brain_circuit_breaker_state` | gauge | Estado del circuit breaker (0=closed, 1=open, 2=half) |
| `brain_enrichment_failures_total` | counter | Fallos de enriquecimiento por fuente |
| `brain_dlq_messages_total` | counter | Mensajes enviados a DLQ |
| `brain_processing_time_seconds` | histogram | Tiempo total de procesamiento por incidente |
| `brain_xai_availability_ratio` | gauge | Ratio de incidentes con XAI vs fallback |

### 12.4 Logging estructurado

```python
structlog.configure(...)
log = structlog.get_logger()

log.info("incident_produced",
    incident_id=incident.incident_id,
    severity=incident.severity,
    alert_count=len(incident.alerts),
    xai_available=incident.xai_available,
    llm_latency_ms=incident.llm_latency_ms,
    processing_time_ms=processing_time
)
```

---

## 13. Consideraciones GDPR

| Requisito | Implementación |
|-----------|---------------|
| **Seudonimización de IPs** | Brain recibe IPs seudonimizadas (hash SHA-256+sal) desde el pipeline de ingesta. No realiza re-identificación. |
| **No persistencia innecesaria** | Brain no almacena datos personales más allá del ciclo de correlación. Los incidentes se persisten en OpenSearch con retención 365 días. |
| **Minimización** | Brain recibe alertas pre-filtradas, no tráfico bruto. Solo procesa lo que los modelos ya han identificado como anómalo. |
| **Acceso restringido** | Los incidentes en OpenSearch están sujetos a RBAC. La re-identificación de IPs requiere control dual (ver doc de compliance). |
| **Audit logging** | Toda consulta de incidentes se audita. Las acciones de Brain (correlación, scoring, acciones recomendadas) se registran con timestamp. |
| **Art. 22 GDPR** | Las decisiones automatizadas (respuestas SOAR) tienen guardrails: acciones destructivas requieren aprobación humana. El nivel de autonomía se gobierna según la matriz de niveles 0–4 del doc de compliance. |

---

## 14. Feedback loop

### 14.1 Propósito

Permite que las respuestas de los analistas del SOC y de Shuffle alimenten a Brain para
mejorar futuras correlaciones:

- **Analista marca FP** → Brain registra el patrón para futuras evaluaciones
- **Analista confirma TP** → Brain refuerza el patrón de correlación
- **Shuffle ejecuta playbook** → Brain registra el resultado para métricas
- **Analista ajusta severidad** → Brain registra el ajuste para calibrar el scorer

### 14.2 Implementación

```python
class FeedbackLoop:
    async def ingest_feedback(self, feedback: AnalystFeedback):
        """Procesa feedback de analistas para mejorar correlaciones futuras."""
        if feedback.verdict == "false_positive":
            await self.register_fp_pattern(feedback.incident_id, feedback.reason)
        elif feedback.verdict == "true_positive":
            await self.reinforce_pattern(feedback.incident_id)
        if feedback.severity_adjustment:
            await self.record_severity_calibration(
                feedback.incident_id,
                feedback.original_severity,
                feedback.adjusted_severity
            )
```

---

## 15. Despliegue

### 15.1 Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-m", "src.main"]
```

### 15.2 Docker Compose (desarrollo)

```yaml
version: "3.8"
services:
  brain:
    build: .
    environment:
      - KAFKA_BOOTSTRAP_SERVERS=kafka:9092
      - LLM_BASE_URL=http://brain-llm:8080
      - REDIS_URL=redis://redis:6379
      - MISP_URL=http://misp:80
      - MISP_API_KEY=${MISP_API_KEY}
      - CLICKHOUSE_URL=http://clickhouse:8123
      - OPENSEARCH_URL=http://opensearch:9200
      - SHUFFLE_URL=http://shuffle:3001
      - SHUFFLE_API_KEY=${SHUFFLE_API_KEY}
      - LOG_LEVEL=INFO
    depends_on:
      - kafka
      - redis
```

### 15.3 Dependencias (requirements.txt)

```
confluent-kafka>=2.3.0
httpx>=0.27.0
tenacity>=8.2.0
pydantic>=2.6.0
redis>=5.0.0
pymisp>=2.4.180
clickhouse-connect>=0.7.0
opensearch-py>=2.4.0
geoip2>=4.8.0
structlog>=24.1.0
pyyaml>=6.0
prometheus-client>=0.20.0
```

---

## 16. Tests

### 16.1 Estrategia

| Nivel | Herramienta | Cobertura |
|-------|------------|-----------|
| **Unitarios** | pytest + pytest-mock | Lógica de correlación, scoring, validación, XAI — sin infraestructura |
| **Integración** | testcontainers | Kafka, Redis, ClickHouse, OpenSearch reales en contenedores efímeros |
| **End-to-end** | Mock LLM + Kafka real | Pipeline completo: alerta → incidente → Shuffle webhook |

### 16.2 Casos de test críticos

1. **Correlación de 3 alertas en ventana de 5 min** → produce 1 incidente con 3 alertas
2. **Alerta única de baja severidad** → no produce incidente (filtrado pre-LLM)
3. **LLM timeout** → fallback graceful, incidente sin XAI, etiquetado para reproceso
4. **LLM alucina IPs** → SchemaValidationError, fallback activado
5. **Circuit breaker abierto** → todas las correlaciones usan fallback
6. **Enriquecimiento parcial** (MISP caído) → incidente con enriquecimiento parcial
7. **Sessionization** (scan a las 10:00, exfil a las 10:25) → 1 incidente con sesión de 30 min
8. **FP detection** (backup nocturno) → Brain marca como FP, no produce incidente
9. **Shuffle webhook** → incidente crítico dispara notificación + ticket
10. **DLQ** → alerta con schema inválido va a DLQ

---

## 17. Dependencias con otros issues

| Issue | Estado | Impacto en Brain |
|-------|--------|-----------------|
| Tuning de modelos con etiquetas de Darktrace | backlog | Mejora la calidad de las alertas que Brain recibe; no bloquea el diseño/implementación del componente |
| Desplegar infraestructura core | backlog | Brain necesita Kafka, Redis, ClickHouse, OpenSearch y MISP operativos para funcionar end-to-end |
| Verificar acceso a API de Darktrace | backlog | Necesario para las métricas comparativas semanales |

> **Nota:** El componente Brain puede diseñarse, implementarse y testearse con mocks
> sin que las dependencias estén resueltas. El funcionamiento end-to-end real requiere
> que la infraestructura core esté desplegada.

---

*Especificación técnica del componente Brain · Versión 1.0 · 2026-07-03*
*Mantenido por el equipo KhaiNet (Grupo Khlloreda / KH7)*
