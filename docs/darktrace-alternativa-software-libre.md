# KhaiNet — Alternativa a Darktrace con Software Libre + Brain

**Documento de arquitectura**
Proyecto: KhaiNet · Plataforma NDR open-source con IA propia
Versión: 1.0 · Fecha: 2026-07-03
Autor: Equipo KhaiNet (Grupo Khlloreda / KH7)

---

## 1. Resumen ejecutivo y motivación

**KhaiNet** es una plataforma de **detección y respuesta a amenazas de red (NDR)** construida íntegramente con **software libre** y **modelos de IA propios**, diseñada para **sustituir Darktrace** en la organización.

### Por qué sustituir Darktrace

| Motivación | Detalle |
|-----------|---------|
| **Soberanía tecnológica** | Darktrace es una caja negra propietaria: los modelos no son auditables ni exportables. KhaiNet pone el control del modelo en manos de la organización. |
| **Coste** | Darktrace implica licensing per-sensor + Antigena (respuesta) + mantenimiento anual. KhaiNet elimina el coste de licencia; el coste restante es infraestructura on-premise. |
| **IA propia y contextual** | Los modelos de Darktrace se entrenan de forma genérica. KhaiNet entrena sobre **el tráfico real de la organización**, capturando su comportamiento específico. |
| **Auditabilidad** | Todo el pipeline es open-source y auditable: captura (Zeek), reglas (Suricata), modelos (Python), correlación (Brain). |
| **Extensibilidad** | Cualquier componente puede ampliarse o sustituirse sin depender de un único proveedor. |

### Principio rector

> **KhaiNet no replica Darktrace funcional a funcional. Construye un NDR equivalente o superior apoyándose en software libre maduro + IA propia + Brain como capa de razonamiento.**

---

## 2. Comparativa Darktrace vs KhaiNet

| Capacidad | Darktrace | KhaiNet |
|-----------|-----------|---------|
| Captura de tráfico | Propietario (sensor appliance) | Zeek + Suricata + Packetbeat (open-source) |
| Detección de anomalías | IA propietaria (Antigena) | Modelos propios: Isolation Forest, Autoencoders, HMM |
| Detección por firmas | Limitada | Suricata + reglas ET Open/Pro |
| Correlación / razonamiento | Propietario | **Brain (LLM propio KH7)** sobre alertas pre-filtradas |
| Respuesta automatizada | Antigena (proprietario) | Shuffle (SOAR open-source) + playbooks |
| SIEM / HIDS | No incluido | Wazuh integrado |
| Visibilidad / inventario | Propietario | ntopng + inventario propio desde Zeek |
| Modelos auditables | ❌ Caja negra | ✅ Código + MLflow + datasets versionados |
| Reentrenamiento | Automático opaco | Continuo, controlado, con drift detection |
| Coste de licencia | Alto (per-sensor + módulos) | 0 (software libre) |
| Soberanía de datos | Datos en appliance propietario | 100% on-premise, propiedad de la organización |
| Personalización | Limitada a configuración | Total (código + modelos + reglas) |
| Tiempo a valor | Rápido (appliance turnkey) | Medio (despliegue + tuning) — mitigado con shadow mode |

### Ventajas del enfoque open-source
- **Sin vendor lock-in**: cada capa es reemplazable.
- **Comunidad activa**: Zeek, Suricata, Wazuh, OpenSearch son proyectos maduros con soporte comercial opcional.
- **Transparencia**: los analistas pueden inspeccionar por qué se generó una alerta (XAI).
- **Coste marginal cero** por sensor adicional: solo hardware.

### Limitaciones a mitigar
- **Esfuerzo de despliegue y tuning**: mayor que un appliance turnkey → mitigado con roadmap por fases y shadow mode.
- **Necesita talento interno**: ingeniería de red + ML → mitigado con documentación y playbooks.
- **Sin soporte 24/7 de un único proveedor** → mitigado con soporte comercial opcional por componente.

---

## 3. Arquitectura general por capas

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         RED DE LA ORGANIZACIÓN                          │
│   (mirror/SPAN, NetFlow/sFlow/IPFIX, packet capture)                    │
└──────────────┬──────────────────────────────────────┬───────────────────┘
               │                                      │
┌──────────────▼──────────┐               ┌───────────▼──────────────┐
│  CAPA 1 — CAPTURA        │               │  CAPA 1b — ENDPOINT/HIDS  │
│  Zeek · Suricata         │               │  Wazuh agent              │
│  ntopng · Packetbeat     │               │  (logs de host, FIM)      │
└──────────────┬───────────┘               └───────────┬──────────────┘
               │                                        │
               ▼                                        ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  CAPA 2 — INGESTA / BUS DE MENSAJES                                      │
│  Filebeat → Apache Kafka (topics: zeek-*, suricata-alerts, wazuh-events) │
└──────────────┬───────────────────────────────────────────┬───────────────┘
               │                                           │
   ┌───────────▼────────────┐                 ┌────────────▼──────────────┐
   │  CAPA 3a — BÚSQUEDA     │                 │  CAPA 3b — ANALYTICS       │
   │  OpenSearch (logs,      │                 │  ClickHouse (series temp., │
   │  alertas, dashboards)   │                 │  features, métricas)       │
   │  Kibana                 │                 │  Grafana                   │
   └───────────┬─────────────┘                 └────────────┬──────────────┘
               │                                            │
               └──────────────────┬─────────────────────────┘
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  CAPA 4 — DETECCIÓN IA (modelos propios, Python)                         │
│  Isolation Forest · Autoencoders · HMM · (Transformers opcional)         │
│  Feature engineering desde ClickHouse · MLflow (versionado)              │
│  → produce scores de anomalía → topic ml-scores                          │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  CAPA 5 — CORRELACIÓN Y RAZONAMIENTO — BRAIN (KH7)                       │
│  LLM propio sobre alertas pre-filtradas:                                 │
│  · Correlación multi-evento  · Enriquecimiento  · Scoring de severidad   │
│  · Reducción de falsos positivos  · Explicabilidad (XAI)                 │
│  → produce incidentes correlacionados → topic brain-incidents            │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  CAPA 6 — RESPUESTA AUTOMATIZADA (SOAR)                                  │
│  Shuffle · TheHive/Cortex · MISP (threat intel)                          │
│  Playbooks: contención, notificación, ticketing, aislamiento             │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  CAPA 7 — VISUALIZACIÓN Y REPORTING                                      │
│  Kibana (logs) · Grafana (métricas/KPIs) · Dashboards propios            │
│  Inventario de activos · Topología · Perfiles de comportamiento          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Principios de diseño

1. **Brain NO es detector en tiempo real.** Opera como capa de razonamiento sobre alertas **pre-filtradas** por los modelos de anomalías y los sistemas basados en reglas. Procesar todo el tráfico con un LLM no es viable por latencia y coste.
2. **Shadow mode de 12 meses.** KhaiNet opera en paralelo con Darktrace. Las alertas de Darktrace se usan como **etiquetas supervisadas** para entrenar y validar los modelos propios.
3. **Pipeline desacoplado vía Kafka.** Los sensores no dependen de la disponibilidad de OpenSearch; Kafka absorbe picos y permite replay para reentrenamiento.
4. **Storage dual.** OpenSearch para búsqueda/dashboards; ClickHouse para analytics y feature engineering a escala.
5. **Todo auditable.** Código, modelos, datasets y decisiones son versionados (Git + MLflow).

---

## 4. Componentes y stack tecnológico detallado por capa

### Capa 1 — Captura y análisis de tráfico

| Componente | Rol | Notas |
|-----------|-----|-------|
| **Zeek** (Bro) | Logging estructurado de conexiones, DNS, HTTP, SSL, archivos, x509 | Núcleo de la visibilidad. Logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `x509.log`, `weird.log` |
| **Suricata** | IDS/IPS basado en reglas (firmas) | Reglas ET Open + ET Pro. Salida `eve.json`. Detección de C2 conocido, exploits, policy violations |
| **ntopng** | Visibilidad de flujos en tiempo real, top talkers | Interfaz web para analistas; complementa Zeek |
| **Elastic Packetbeat** | Decodificación de protocolos de aplicación (L7) | HTTP, DNS, TLS, MySQL, Redis, etc. desde SPAN |
| **nfcapd / nfdump** | Recolección de NetFlow/sFlow/IPFIX | Para entornos sin SPAN disponible |

### Capa 1b — Endpoint / HIDS

| Componente | Rol |
|-----------|-----|
| **Wazuh agent** | Logs de host, file integrity monitoring (FIM), inventario de software, compliance, detección de rootkit |

### Capa 2 — Ingesta / bus de mensajes

| Componente | Rol |
|-----------|-----|
| **Filebeat** | Shipper ligero en cada sensor → envía a Kafka |
| **Apache Kafka** | Bus de mensajes desacoplado, buffer persistente, replay |
| **Logstash** | Consume de Kafka, normaliza/enriquece (GeoIP, asset lookup) → OpenSearch |
| **Kafka Connect** | Sink connectors a OpenSearch y ClickHouse (alto volumen) |

**Topics de Kafka:**
`zeek-conn`, `zeek-dns`, `zeek-http`, `zeek-ssl`, `zeek-files`, `suricata-alerts`, `packetbeat-flows`, `wazuh-events`, `ml-scores`, `brain-incidents`

### Capa 3a — Búsqueda y dashboards (OpenSearch)

| Componente | Rol |
|-----------|-----|
| **OpenSearch** | Indexación full-text, búsqueda, alerting por queries |
| **Kibana / OpenSearch Dashboards** | Exploración de logs, dashboards interactivos |

- **Retención**: hot 30 días (SSD), warm 90 días (HDD), cold 1 año (object storage)
- **Index pattern**: `zeek-conn-2026.07.03`, `suricata-alerts-2026.07.03` (rotación diaria)
- **Tamaño estimado**: 1–5 TB para 30 días de hot data

### Capa 3b — Analytics de series temporales (ClickHouse)

| Componente | Rol |
|-----------|-----|
| **ClickHouse** | Agregaciones temporales rápidas, feature engineering para ML, baselines estadísticas |
| **Grafana** | Dashboards de métricas temporales y KPIs |

- **Retención**: 12 meses (compresión columnar 10–50x)
- **Esquema**: tablas MergeTree particionadas por día, materialized views para agregaciones
- **Tamaño estimado**: 100–500 GB para 12 meses

### Capa 4 — Detección IA (modelos propios)

| Componente | Rol |
|-----------|-----|
| **Python (scikit-learn, PyTorch)** | Implementación de modelos |
| **MLflow** | Versionado de modelos, experimentos, tracking de métricas |
| **Kafka consumer (ML)** | Lee features de ClickHouse, produce scores a `ml-scores` |

### Capa 5 — Correlación y razonamiento (Brain)

| Componente | Rol |
|-----------|-----|
| **Brain (LLM propio KH7)** | Razonamiento sobre alertas pre-filtradas: correlación, enriquecimiento, scoring, XAI |

### Capa 6 — Respuesta automatizada (SOAR)

| Componente | Rol |
|-----------|-----|
| **Shuffle** | Orquestación SOAR open-source: playbooks, integraciones |
| **TheHive / Cortex** | Gestión de incidentes + analizadores automatizados (alternativa/complemento) |
| **MISP** | Threat intelligence sharing, IOCs |

### Capa 7 — Visualización y reporting

| Componente | Rol |
|-----------|-----|
| **Kibana** | Exploración de logs y alertas |
| **Grafana** | Métricas temporales, KPIs, SLA |
| **Dashboards propios** | Vistas de inventario, topología, perfiles de comportamiento |

---

## 5. Capa de correlación con Brain

Brain es el **cerebro de razonamiento** de KhaiNet. No detecta en tiempo real; **razona sobre alertas pre-filtradas** para convertir ruido en señales accionables.

### Rol de Brain en el pipeline

```
Modelos de anomalías (Isolation Forest, Autoencoders, HMM)
        + Alertas de reglas (Suricata, Wazuh)
        + Eventos de contexto (asset inventory, GeoIP, threat intel)
                │
                ▼
        ┌───────────────┐
        │    BRAIN      │  ← LLM propio KH7
        │  (correlación) │
        └───────┬───────┘
                ▼
   Incidentes correlacionados + score de severidad + explicación (XAI)
                │
                ▼
           Shuffle (SOAR) → respuesta automatizada
```

### Funciones de Brain

1. **Correlación multi-evento**: agrupa alertas dispersas en un único incidente coherente (ej.: scan → login anómalo → exfiltración = campaña).
2. **Enriquecimiento**: combina datos de asset inventory, GeoIP, threat intel (MISP) y contexto histórico para dar significado a cada alerta.
3. **Scoring de severidad**: asigna un score 0–100 a cada incidente basado en contexto, criticidad del activo, y confianza del modelo.
4. **Reducción de falsos positivos**: descarta alertas que, con contexto, son comportamiento legítimo (backups nocturnos, scans de vulnerabilidad autorizados, etc.).
5. **Explicabilidad (XAI)**: genera una narrativa en lenguaje natural de por qué se generó el incidente, qué eventos lo componen y qué se recomienda.
6. **Priorización**: ordena incidentes para que el SOC atienda primero los de mayor impacto.

### Por qué Brain NO procesa todo el tráfico

- **Latencia**: un LLM no puede procesar millones de eventos/segundo.
- **Coste**: razonar sobre cada paquete es inviable.
- **Valor**: la mayoría del tráfico es benigno; el razonamiento aporta valor sobre **alertas candidatas**, no sobre tráfico bruto.

> **Brain opera sobre la salida pre-filtrada de los modelos de anomalías y reglas, no sobre el tráfico en crudo.**

---

## 6. Modelos de IA propios

### Pipeline de datos para ML

```
ClickHouse (features pre-calculadas)
        │
        ▼
Feature engineering (Python)
  · Por host/servicio: bytes, pkts, duración, destinos únicos, DNS queries
  · Temporales: hora, día, estacionalidad
  · De comportamiento: frecuencia, regularidad, desviación del baseline
        │
        ▼
Modelos (MLflow-tracked)
  · Isolation Forest  → score de anomalía de conexión
  · Autoencoder       → error de reconstrucción > p99 baseline
  · HMM               → secuencia de estados (normal/scan/exfil/C2)
        │
        ▼
Scores → Kafka (ml-scores) → Brain
```

### Modelos

| Modelo | Tipo | Detección | Entradas |
|--------|------|-----------|----------|
| **Isolation Forest** | No supervisado | Conexiones atípicas | bytes, duración, destinos, DNS, horario, geolocalización |
| **Autoencoder** | No supervisado (reconstrucción) | Desviación de patrón normal por host/servicio | Vector de features de comportamiento; umbral en error de reconstrucción > p99 del baseline |
| **HMM** | No supervisado (secuencial) | Transiciones de estado anómalas | Secuencias temporales de comportamiento; estados ocultos: normal, scan, exfil, C2 |
| **Transformers** (opcional, fase avanzada) | Secuencia | Patrones temporales complejos | Secuencias de eventos por host |

### Entrenamiento sobre tráfico de la organización

- **Baseline**: 4–6 semanas de tráfico normal para establecer el comportamiento esperado por host/servicio.
- **Etiquetas supervisadas (shadow mode)**: las alertas de Darktrace se usan como etiquetas para validar y afinar los modelos.
- **Reentrenamiento continuo**: semanal/quincenal, con **drift detection** (PSI, KS-test) que dispara reentrenamiento cuando la distribución del tráfico cambia significativamente.

### MLflow

- Cada ejecución de entrenamiento se trackea: hiperparámetros, métricas (precision, recall vs etiquetas Darktrace), artefactos (modelo serializado).
- Versionado de datasets: snapshots de features usadas en cada entrenamiento.
- Promoción de modelos: `staging` → `production` tras validación.

---

## 7. Flujo de datos end-to-end

```
1. Paquete capturado en SPAN/mirror del core switch
        │
2. Zeek genera conn.log, dns.log, http.log, ssl.log, files.log
   Suricata genera eve.json (alertas de reglas)
   Packetbeat decodifica L7
   Wazuh agent envía logs de host
        │
3. Filebeat envía logs a Kafka (topics por tipo)
        │
4. Logstash/Kafka Connect normaliza y enriquece:
   · GeoIP sobre IPs de destino
   · Asset lookup (¿IP = servidor crítico? ¿workstation? ¿IoT?)
   · Threat intel lookup (MISP)
        │
5. OpenSearch indexa logs (búsqueda/dashboards)
   ClickHouse agrega features (analytics/ML)
        │
6. ML pipeline consume features de ClickHouse:
   · Isolation Forest → score de anomalía de conexión
   · Autoencoder → error de reconstrucción
   · HMM → transición de estado anómala
   · Scores → Kafka (ml-scores)
        │
7. Brain consume alertas pre-filtradas (ml-scores + suricata + wazuh):
   · Correlaciona eventos dispersos en incidentes
   · Enriquece con contexto
   · Asigna score de severidad
   · Genera explicación (XAI)
   · Incidentes → Kafka (brain-incidents)
        │
8. Shuffle (SOAR) ejecuta playbooks según severidad:
   · Crítico → aislamiento de host + notificación SOC + ticket
   · Alto → notificación + ticket
   · Medio → ticket + monitorización
        │
9. SOC ve el incidente en TheHive/dashboards con explicación de Brain
   y actúa (o confirma la respuesta automatizada)
```

**Latencia objetivo (captura → alerta accionable):** comparable a Darktrace (±30%).

---

## 8. Detección de amenazas específicas

| Amenaza | Señales | Detección |
|---------|---------|-----------|
| **C2 / beaconing** | Conexiones periódicas a IP poco frecuente; DNS a dominios DGA; TLS a certificados sospechosos | Isolation Forest (regularidad temporal) + Suricata (reglas ET) + HMM (estado C2) + Brain (correlación DNS+conn+SSL) |
| **Lateral movement** | Nuevas conexiones entre segmentos; uso de puertos atípicos; SMB/RDP anómalo; PsExec/WMI | Autoencoder (desviación por host) + HMM (transición scan→lateral) + Wazuh (logon events) |
| **Exfiltración de datos** | Volumen de bytes saliente anómalo; transferencias a almacenamiento cloud; DNS tunneling; conexiones largas a destinos raros | Isolation Forest (bytes salientes) + Zeek files.log + Brain (correlación volumen+destino+horario) |
| **Beaconing** | Intervalos regulares de conexión; jitter bajo; destinos no resueltos | Análisis de periodicidad sobre conn.log + HMM |
| **Anomalías de comportamiento** | Desviación del baseline por host/usuario; horario inusual; destinos nuevos | Autoencoder + Isolation Forest + baseline estadístico en ClickHouse |
| **DNS tunneling** | Queries largas, alta entropía, TXT records frecuentes, volumetría DNS anómala | Zeek dns.log + heurísticas + Isolation Forest |
| **Scan / reconnaissance** | Múltiples destinos en corto tiempo; puertos no usados habitualmente | HMM (estado scan) + Suricata (reglas) |

---

## 9. Respuesta automatizada

### SOAR: Shuffle (+ TheHive/Cortex)

| Severidad | Playbook | Acciones |
|-----------|----------|----------|
| **Crítico (80–100)** | Contención inmediata | Aislamiento de host (firewall/EDR), bloqueo de IP en perimeter, notificación SOC (Teams/email), ticket crítico en TheHive, captura de evidencias |
| **Alto (60–79)** | Investigación acelerada | Notificación SOC, ticket, enriquecimiento automático (Cortex analyzers), recolección de contexto adicional |
| **Medio (40–59)** | Monitorización | Ticket, monitorización, re-evaluación por Brain si aparecen eventos correlacionados |
| **Bajo (0–39)** | Logging | Registro en OpenSearch, sin acción inmediata |

### Integraciones
- **Firewall / EDR**: aislamiento de hosts, bloqueo de IPs.
- **TheHive**: gestión de incidentes, casos, tareas.
- **Cortex**: analizadores automatizados (VirusTotal, AbuseIPDB, etc.).
- **MISP**: threat intel bidireccional.
- **Teams/Email**: notificación al SOC.
- **Identity (Azure AD/AD)**: contexto de usuario, grupos, privilegios.

### Guardrails de seguridad
- Las acciones de contención automática (aislamiento, bloqueo) requieren **aprobación humana** salvo en incidentes críticos pre-aprobados en el playbook.
- Toda acción se audita y es reversible.

---

## 10. Visibilidad e inventario

### Asset discovery (pasivo)
- Zeek `conn.log` + `dns.log` → inventario de hosts activos, servicios, destinos.
- Wazuh → inventario de software, OS, parches.
- ntopng → topología de flujos en tiempo real.

### Perfiles de comportamiento
- Por host: destinos habituales, puertos, volumen, horario, servicios.
- Por usuario: patrones de acceso, recursos, horario.
- Baseline estadístico en ClickHouse (media, desviación, percentiles por ventana temporal).

### Topología
- Grafo de comunicaciones derivado de Zeek (quién habla con quién, qué puertos).
- Visualización en Grafana/dashboards propios.

---

## 11. Infraestructura y despliegue

### Modelo: on-premise, escalabilidad horizontal, alta disponibilidad

```
┌─────────────── NODO SENSOR (por segmento de red) ───────────────┐
│  Zeek · Suricata · Packetbeat · Filebeat · Wazuh agent          │
│  (probe con SPAN/mirror del switch)                             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CLUSTER KAFKA (3+ brokers, HA)                                 │
└──────┬───────────────────────────────────────┬──────────────────┘
       │                                       │
┌──────▼───────────────┐          ┌────────────▼───────────────┐
│  CLUSTER OPENSEARCH   │          │  CLUSTER CLICKHOUSE         │
│  (3+ nodos, HA)       │          │  (3+ nodos, replicación)    │
│  + Kibana             │          │  + Grafana                  │
└──────┬────────────────┘          └────────────┬───────────────┘
       │                                        │
┌──────▼────────────────────────────────────────▼───────────────┐
│  NODOS ML (GPU opcional para Transformers)                     │
│  Python + MLflow + Kafka consumer                              │
└──────────────────────────────┬─────────────────────────────────┘
                               │
┌──────────────────────────────▼─────────────────────────────────┐
│  BRAIN (servicio LLM propio KH7)                                │
│  + Shuffle (SOAR) + TheHive + Cortex + MISP                    │
└────────────────────────────────────────────────────────────────┘
```

### Requisitos de hardware (orientativo, por despliegue medio)

| Componente | CPU | RAM | Disco | Notas |
|-----------|-----|-----|-------|-------|
| Sensor (Zeek+Suricata) | 8–16 vCPU | 16–32 GB | 500 GB SSD | 1 por segmento de red crítico |
| Kafka (3 brokers) | 4–8 vCPU | 8–16 GB | 1 TB SSD c/u | Replicación factor 3 |
| OpenSearch (3 nodos) | 8–16 vCPU | 32–64 GB | 2–5 TB SSD c/u | Hot/warm/cold tiering |
| ClickHouse (3 nodos) | 8 vCPU | 16–32 GB | 500 GB–1 TB c/u | Compresión columnar |
| ML nodes | 8–16 vCPU | 32–64 GB | 500 GB | GPU opcional (Transformers) |
| Brain + SOAR | 8 vCPU | 16–32 GB | 200 GB | Según modelo LLM |

### Despliegue
- **Docker / Docker Compose** para entornos pequeños/medios.
- **Kubernetes** para escalabilidad horizontal y HA en entornos grandes.
- **Infraestructura como código**: Ansible/Terraform para reproducibilidad.
- **Alta disponibilidad**: clusters de 3+ nodos en Kafka, OpenSearch, ClickHouse.

---

## 12. Roadmap por sprints (alineado con metodología agile)

### Fase 1 — Infraestructura (Sprints 1–2, 2–3 semanas)
- [ ] Desplegar Zeek, Suricata, Wazuh, OpenSearch, Kafka, ClickHouse, Shuffle
- [ ] Configurar SPAN/mirror en switches críticos
- [ ] Verificar acceso a API de Darktrace (export de alertas como etiquetas) **[BLOCKER si no hay acceso]**
- [ ] Pipeline de ingesta funcional: sensor → Kafka → OpenSearch/ClickHouse

### Fase 2 — Baseline (Sprints 3–5, 4–6 semanas)
- [ ] Capturar tráfico y construir baseline estadístico por host/servicio
- [ ] Implementar feature engineering en ClickHouse
- [ ] Entrenar modelos base (Isolation Forest, Autoencoder)
- [ ] MLflow operativo

### Fase 3 — Tuning (Sprints 6–9, 8–12 semanas)
- [ ] Ajustar umbrales usando etiquetas de Darktrace (shadow mode)
- [ ] Iterar modelos: HMM, drift detection
- [ ] Validar precisión/recall vs Darktrace

### Fase 4 — Semi-activo + Brain (Sprints 10–13, 8–12 semanas)
- [ ] Alertas visibles (no accionadas) en dashboards
- [ ] Integrar Brain como capa de correlación/razonamiento
- [ ] Comparar métricas (cobertura, precisión, ventaja, latencia)

### Fase 5 — Activo controlado (Sprints 14–15, 4–8 semanas)
- [ ] KhaiNet como fuente secundaria de detección
- [ ] Respuestas automatizadas controladas (con aprobación humana)
- [ ] Decisión go/no-go para retirada de Darktrace

### Criterio de salida del shadow mode
Las 4 métricas deben cumplirse **simultáneamente durante 4 semanas consecutivas**:

| Métrica | Objetivo | Definición |
|---------|----------|------------|
| Cobertura | > 90% | % de incidentes de Darktrace que KhaiNet también detecta |
| Precisión | > 85% | % de alertas de KhaiNet que son verdaderos positivos |
| Ventaja | > 0 | Nº de incidentes que KhaiNet detecta y Darktrace no (≥ 0) |
| Latencia | Comparable | Tiempo captura→alerta comparable a Darktrace (±30%) |

---

## 13. Riesgos y mitigaciones

| # | Riesgo | Severidad | Mitigación |
|---|--------|-----------|------------|
| 1 | **Acceso a API de Darktrace no verificado** (BLOCKER) | Crítico | La estrategia de shadow mode depende de exportar alertas como etiquetas. Si no hay API, rediseñar: export manual, etiquetado manual, o usar Darktrace console export. **Verificar en Fase 1.** |
| 2 | Estimación de esfuerzo optimista (7–10 días) | Alto | Realista ~2–3 semanas solo para infra + tuning continuo. Roadmap refleja plazos reales. |
| 3 | Coste de infra (CPU/RAM/storage OpenSearch) subestimado | Alto | Estudio de dimensionamiento en Fase 1; tiering hot/warm/cold para contener coste. |
| 4 | Falsos positivos excesivos en modelos no supervisados | Alto | Tuning con etiquetas Darktrace + Brain como reductor de FP + feedback del SOC. |
| 5 | Drift de tráfico no detectado | Medio | Drift detection (PSI, KS-test) con reentrenamiento automático. |
| 6 | Brain genera explicaciones incorrectas (alucinación) | Medio | Brain opera sobre datos estructurados (no texto libre); XAI con trazas de eventos; revisión humana en críticos. |
| 7 | Pérdida de paquetes en SPAN a alto volumen | Medio | Sizing de sensores; monitorización de drops; ntopng para validar cobertura. |
| 8 | Falta de talento interno (red + ML) | Medio | Documentación, playbooks, formación del SOC. |
| 9 | Cumplimiento (GDPR, gobernanza, cadena de custodia) | Medio | Pendiente: añadir apartado de cumplimiento, roles, retención de PII, cadena de custodia de evidencias. |
| 10 | Dependencia de componentes open-source sin soporte | Bajo | Soporte comercial opcional por componente (Elastic, OpenSearch, Wazuh). |

---

## 14. Métricas de éxito / KPIs

### KPIs de detección (criterio de salida del shadow mode)

| KPI | Objetivo | Definición |
|-----|----------|------------|
| Cobertura | > 90% | % de incidentes de Darktrace que KhaiNet también detecta |
| Precisión | > 85% | % de alertas de KhaiNet que son verdaderos positivos |
| Ventaja | > 0 | Nº de incidentes que KhaiNet detecta y Darktrace no |
| Latencia (MTTD) | Comparable (±30%) | Tiempo medio captura → alerta accionable |

### KPIs operativos

| KPI | Objetivo | Definición |
|-----|----------|------------|
| Falsos positivos | < 15% | % de alertas que el SOC descarta como benignas |
| MTTD | < 10 min | Mean Time To Detect |
| MTTR | < 60 min | Mean Time To Respond (con SOAR) |
| Cobertura de red | > 95% | % de segmentos críticos con sensor activo |
| Uptime de la plataforma | > 99.5% | Disponibilidad del pipeline de detección |

### KPIs de coste

| KPI | Objetivo | Definición |
|-----|----------|------------|
| Coste total vs Darktrace | < 40% del TCO Darktrace | Coste infra + esfuerzo interno vs licensing Darktrace |
| Coste marginal por sensor | ≈ 0 (solo hardware) | Sin coste de licencia por sensor adicional |

---

## Apéndice A — Decisiones técnicas registradas

1. **Kafka como bus de mensajes central** — desacopla captura de almacenamiento/procesamiento; buffer persistente y replay para reentrenamiento.
2. **Storage dual OpenSearch + ClickHouse** — OpenSearch para búsqueda/dashboards; ClickHouse para analytics y feature engineering a escala (10–100x más rápido en agregaciones).
3. **SOAR con Shuffle** (+ TheHive/Cortex + MISP) — orquestación open-source de respuestas automatizadas.
4. **Brain como capa de razonamiento, no detector en tiempo real** — opera sobre alertas pre-filtradas para evitar latencia/coste inviables.
5. **Shadow mode de 12 meses** — Darktrace como fuente de etiquetas supervisadas para validar modelos.

## Apéndice B — Referencias de componentes

- Zeek: https://zeek.org
- Suricata: https://suricata.io
- Wazuh: https://wazuh.com
- OpenSearch: https://opensearch.org
- ClickHouse: https://clickhouse.com
- Apache Kafka: https://kafka.apache.org
- MLflow: https://mlflow.org
- Shuffle: https://shuffler.io
- TheHive: https://thehive-project.org
- Cortex: https://thehive-project.org
- MISP: https://www.misp-project.org
- ntopng: https://www.ntop.org
- Elastic Packetbeat: https://www.elastic.co/beats/packetbeat

---

*Documento de arquitectura KhaiNet · Versión 1.0 · 2026-07-03*
*Mantenido por el equipo KhaiNet (Grupo Khlloreda / KH7)*
