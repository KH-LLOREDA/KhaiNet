# KhaiNet — Estudio de dimensionamiento y costes de infraestructura

> **Documento:** Dimensionamiento detallado de infraestructura
> **Proyecto:** KhaiNet · NDR open-source con IA propia
> **Versión:** 1.0 · Fecha: 2026-07-03
> **Issue:** Estudio de dimensionamiento y costes de infraestructura
> **Vinculado a:** [Arquitectura KhaiNet](darktrace-alternativa-software-libre.md) — Sección 11, Riesgo #3
> **Vinculado a:** [Cumplimiento GDPR](compliance-gobernanza.md) — Sección 3 (política de retención)

> **Convención de unidades**: Todas las capacidades de storage se expresan en TB/GB binarios (TiB/GiB: 1 TB = 1024 GB, 1 GB = 1024 MB). Los precios de hardware se expresan por GB binario. En contextos comerciales, los fabricantes pueden usar TB decimal (1 TB = 1000 GB), lo que resultaría en ~7% menos capacidad real; este margen está absorbido por el headroom de los cálculos.

---

## 1. Resumen ejecutivo

El presente estudio responde al **Riesgo #3** del documento de arquitectura: *"Coste de infra (CPU/RAM/storage OpenSearch) subestimado"*. El análisis confirma que la estimación original de *"1–5 TB para 30 días de hot data"* era **insuficiente en un orden de magnitud** para una organización mediana-grande.

### Hallazgos clave

| Métrica | Estimación original | Estimación corregida (mediana, 180d) | Factor |
|---------|--------------------|---------------------------------------|--------|
| Storage OpenSearch hot (30d) | 1–5 TB | **6.8 TB** | 1.4–6.8x |
| Storage OpenSearch total (365d) | No especificado | **30 TB** | — |
| CPU total cluster | 24–48 vCPU | **133 vCPU** | 2.8–5.5x |
| RAM total cluster | 80–160 GB | **632 GB** | 3.9–7.9x |
| Coste mensual on-premise | No cuantificado | **~2.600 €/mes** | — |

### Conclusión de costes

A pesar del dimensionamiento corregido (significativamente mayor que la estimación original), **KhaiNet on-premise cuesta un 94% menos que Darktrace** en ambos escenarios. El ROI es de **16x–18x** en on-premise y **6x** en cloud. El coste diferencial real no es la infraestructura, sino el **personal especializado** (ingeniería de red + ML + SOC), que debe contabilizarse en el TCO.

### Recomendación

Desplegar en **Proxmox VE on-premise** con tiering hot/warm/cold en OpenSearch. El coste de infraestructura es marginal frente al ahorro vs Darktrace. El factor crítico de éxito es el talento interno, no el hardware.

---

## 2. Metodología y supuestos

### 2.1 Escenarios de organización

Se definen dos escenarios representativos, basados en el perfil de organización que típicamente despliega Darktrace (mediana-grande empresa con presupuesto de ciberseguridad):

| Parámetro | Mediana | Grande |
|-----------|---------|--------|
| Usuarios | 750 (rango 500–1000) | 3.500 (rango 2000–5000) |
| Hosts totales | ~1.200 | ~6.000 |
| Agentes Wazuh | 300 | 1.500 |
| Ancho de banda promedio | 1.5 Gbps | 5.0 Gbps |
| Ancho de banda pico | 3.0 Gbps | 10.0 Gbps |
| Segmentos de red (sensores) | 3 | 6 |

### 2.2 Política de retención (del documento de compliance GDPR)

Los plazos de retención están definidos en `docs/compliance-gobernanza.md` (Sección 3.2):

| Tipo de dato | Retención | Almacenamiento |
|-------------|-----------|----------------|
| Logs de red Zeek (conn, dns, http, ssl) | **180 días** | OpenSearch (hot 30d SSD, warm 30-180d HDD) |
| Alertas Suricata (eve.json alerts) | **365 días** | OpenSearch |
| Eventos Suricata (flow, http, dns, tls) | **90 días** ¹ | OpenSearch |
| Logs Wazuh (syslog, auth, syscheck) | **365 días** | OpenSearch |

> ¹ **Eventos Suricata vs Alertas Suricata**: El documento de compliance define "Alertas Suricata (eve.json alerts): 365 días". Este estudio distingue entre **eventos** (todos los registros de eve.json: flow, http, dns, tls) y **alertas** (solo los registros que disparan una regla). Los eventos se retienen 90 días (volumen alto, valor forense decreciente) y las alertas 365 días (volumen bajo, valor forense alto). Esta distinción debería incorporarse al documento de compliance en una futura revisión.
| Alertas de Brain (correlaciones) | **365 días** | OpenSearch |
| PCAP completo | **30 días** | Almacenamiento dedicado |
| Kafka topics (bus transitorio) | **48 horas** | Kafka (replicación factor 3) |
| ClickHouse (analytics, features) | **180 días** | ClickHouse (compresión columnar) |
| Incidentes confirmados | **5 años** | Archive WORM |
| Logs de auditoría SOC | **5 años** | Archive WORM |

### 2.3 Fuentes de los benchmarks de volumen

Los tamaños de eventos y ratios se basan en:

- **Zeek**: esquema oficial de logs TSV/JSON de Zeek (zeek.org documentation). Tamaños de campos verificados contra el esquema real de `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`.
- **Suricata**: formato `eve.json` (Suricata documentation). Cada evento es un JSON con campos comunes + campos específicos de tipo de evento.
- **Wazuh**: documentación oficial de Wazuh y benchmarks de la comunidad (wazuh.com, foros).
- **OpenSearch**: documentación oficial de OpenSearch sobre sizing, sharding y best practices (opensearch.org/docs).
- **Modelos de IA**: benchmarks de scikit-learn (Isolation Forest), PyTorch (Autoencoders) y hmmlearn (HMM).

> **Nota de transparencia:** Los benchmarks de volumen de red (eventos/día por Gbps) son estimaciones basadas en experiencia de la industria. El volumen real depende del perfil de tráfico específico de cada organización. Se recomienda validar con una captura piloto de 1 semana antes de comprometer el hardware definitivo.

---

## 3. Estimación de volumen de logs por día

### 3.1 Logs de Zeek

Zeek genera logs estructurados por tipo de evento de red. Los logs principales y sus características:

| Log | Campos principales | Bytes/evento (JSON) | % del total |
|-----|-------------------|---------------------|-------------|
| `conn.log` | ts, uid, orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, history, orig_pkts, resp_pkts | ~300 | 60% |
| `dns.log` | ts, uid, orig_h, orig_p, resp_h, resp_p, proto, query, qclass, qtype, rcode, answers, TTLs | ~250 | 20% |
| `http.log` | ts, uid, orig_h, orig_p, resp_h, resp_p, method, host, uri, referrer, version, user_agent, request_body_len, response_body_len, status_code, status_msg | ~500 | 10% |
| `ssl.log` | ts, uid, orig_h, orig_p, resp_h, resp_p, version, cipher, curve, server_name, resumed, subject, issuer, client_subject, client_issuer | ~350 | 5% |
| `files.log` | ts, fuid, uid, source, depth, analyzers, mime_type, filename, duration, local_orig, local_resp, seen_bytes, total_bytes | ~250 | 3% |
| `weird.log` | ts, uid, orig_h, orig_p, resp_h, resp_p, name, addl, notice, peer | ~120 | 2% |

**Eventos por día**: Una red con 1 Gbps de tráfico promedio genera aproximadamente 1.000–2.000 conexiones/segundo, lo que equivale a ~86–173M conexiones/día. Para los escenarios:

| Escenario | Gbps | Conexiones/día (conn.log) | Eventos totales/día | Volumen/día |
|-----------|------|---------------------------|---------------------|-------------|
| Mediana | 1.5 | 100M | 167M | **47.7 GB** |
| Grande | 5.0 | 350M | 583M | **167.0 GB** |

**Desglose por tipo de log (escenario mediana)**:

| Log | Eventos/día | Volumen/día |
|-----|-------------|-------------|
| conn.log | 100.000.000 | 28.610 MB (27.9 GB) |
| dns.log | 33.333.333 | 7.947 MB (7.8 GB) |
| http.log | 16.666.666 | 7.947 MB (7.8 GB) |
| ssl.log | 8.333.333 | 2.782 MB (2.7 GB) |
| files.log | 5.000.000 | 1.192 MB (1.2 GB) |
| weird.log | 3.333.333 | 382 MB (0.4 GB) |
| **TOTAL** | **166.666.666** | **48.860 MB (47.7 GB)** |

**Desglose por tipo de log (escenario grande)**:

| Log | Eventos/día | Volumen/día |
|-----|-------------|-------------|
| conn.log | 350.000.000 | 100.136 MB (97.8 GB) |
| dns.log | 116.666.666 | 27.816 MB (27.2 GB) |
| http.log | 58.333.333 | 27.816 MB (27.2 GB) |
| ssl.log | 29.166.666 | 9.735 MB (9.5 GB) |
| files.log | 17.500.000 | 4.172 MB (4.1 GB) |
| weird.log | 11.666.666 | 1.335 MB (1.3 GB) |
| **TOTAL** | **583.333.333** | **171.010 MB (167.0 GB)** |

### 3.2 Logs de Suricata

Suricata genera eventos `eve.json` (formato JSON) para cada flujo que inspecciona. La configuración recomendada para KhaiNet incluye:

- **Alert events**: alertas disparadas por reglas ET Open/Pro
- **Flow events**: inicio/fin de flujos (metadata de conexión)
- **Protocol events**: HTTP, DNS, TLS, SMB (metadata de protocolos L7)

**Parámetros**:
- Tamaño promedio por evento: ~600 bytes (eve.json es más verboso que Zeek TSV)
- Ratio de eventos: 1.2x los eventos de `conn.log` de Zeek (Suricata registra más tipos de eventos de protocolo)
- Ratio de alertas: ~0.05% del total de eventos (la mayoría son flow/protocol events, no alertas)

| Escenario | Eventos totales/día | Alertas/día | Volumen total/día | Volumen solo alertas/día |
|-----------|---------------------|-------------|-------------------|--------------------------|
| Mediana | 120M | 60.000 | **67.1 GB** | 34 MB |
| Grande | 420M | 210.000 | **234.7 GB** | 120 MB |

> **Nota**: El volumen de Suricata es mayor que el de Zeek porque eve.json es más verboso (JSON con campos anidados) y registra eventos de protocolo adicionales. Si se configura Suricata para emitir solo alertas (sin flow/protocol events), el volumen cae a ~34–120 MB/día, pero se pierde visibilidad de flujos.

### 3.3 Logs de Wazuh

Wazuh agent envía logs desde los endpoints: auth.log, syslog, syscheck (FIM), rootcheck, inventario de hardware/software, y detección de vulnerabilidades.

**Parámetros**:
- Volumen promedio por agente: ~10 MB/día (workstations: 3–10 MB, servidores: 15–30 MB, promedio ponderado: 10 MB)
- Overhead del Wazuh manager: +10% (logs propios del manager, análisis, alertas)

| Escenario | Agentes | Volumen/día |
|-----------|---------|-------------|
| Mediana | 300 | **3.2 GB** (3.300 MB) |
| Grande | 1.500 | **16.1 GB** (16.500 MB) |

### 3.4 Resumen de volumen total

| Componente | Mediana (GB/día) | Grande (GB/día) |
|-----------|------------------|-----------------|
| Zeek | 47.7 | 167.0 |
| Suricata | 67.1 | 234.7 |
| Wazuh | 3.2 | 16.1 |
| **TOTAL** | **118.0** | **417.8** |
| **TOTAL (TB/día)** | **0.115** | **0.408** |

> **Observación**: Suricata es el mayor generador de volumen (57% del total) debido al formato JSON verboso de eve.json. Zeek representa el 40% y Wazuh el 3%. Optimizar la configuración de Suricata (reducir eventos de protocolo no esenciales) puede reducir el volumen total en un 30–40%.

---

## 4. Requisitos de storage

### 4.1 OpenSearch — data lake principal

OpenSearch es el componente más demandante de storage. El cálculo del overhead sobre los logs raw se basa en:

| Factor | Valor | Justificación |
|--------|-------|---------------|
| Compresión ZSTD | 0.85x | Compresión recomendada para logs (mejor que LZ4 por defecto) |
| Réplicas (factor 1) | 2.0x | 1 réplica = 2 copias totales (HA) |
| Overhead (mapping, merge, metadata) | 1.15x | Índice invertido + source field + segment merge space |
| **Factor total** | **1.955x** | raw × 1.955 = storage OpenSearch |

> **Nota sobre el factor de overhead**: El factor 1.955x asume compresión ZSTD uniforme. En la práctica, el índice invertido de OpenSearch no se comprime igual que el campo `_source` (JSON original). Un factor más conservador sería 2.0–2.2x. Para estimaciones de provisioning de hardware, se recomienda usar 2.2x como techo conservador, lo que incrementaría el storage en ~13%. Los cálculos de este documento usan 1.955x como estimación central; el Apéndice B permite ajustar este parámetro.

**Storage por retención** (datos raw → OpenSearch con overhead):

#### Escenario mediana

| Retención | Raw (GB) | OpenSearch (GB) | OpenSearch (TB) | Hot SSD 30d (GB) | Warm HDD (GB) |
|-----------|----------|-----------------|-----------------|-------------------|---------------|
| 90 días | 10.622 | 20.767 | **20.3** | 6.920 | 13.846 |
| 180 días | 15.210 | 29.735 | **29.0** | 6.920 | 22.815 |
| 365 días | 15.812 | 30.913 | **30.2** | 6.920 | 23.992 |

> Entre 180 y 365 días el incremento es mínimo (~4%) porque Zeek (el mayor volumen) tiene retención máxima de 180 días. Solo Suricata alertas y Wazuh extienden a 365 días, y su volumen es pequeño.

#### Escenario grande

| Retención | Raw (GB) | OpenSearch (GB) | OpenSearch (TB) | Hot SSD 30d (GB) | Warm HDD (GB) |
|-----------|----------|-----------------|-----------------|-------------------|---------------|
| 90 días | 37.613 | 73.534 | **71.8** | 24.504 | 49.030 |
| 180 días | 54.104 | 105.774 | **103.3** | 24.504 | 81.269 |
| 365 días | 57.107 | 111.644 | **109.0** | 24.504 | 87.139 |

### 4.2 ClickHouse — analytics y feature engineering

ClickHouse almacena features agregadas (no logs raw) para ML y dashboards temporales.

| Parámetro | Valor |
|-----------|-------|
| Ratio de features vs raw | 5% del volumen de logs raw |
| Compresión columnar | 15x (MergeTree con codecs LZ4/ZSTD) |
| Retención | 180 días |

> **Nota sobre retención de ClickHouse**: El documento de arquitectura (Sección 3b) menciona "12 meses" para ClickHouse, mientras que el documento de compliance (Sección 3.2) establece 180 días. Este estudio usa 180 días (alineado con la retención de Zeek, que es la fuente principal de features). Si se requiere retención de 12 meses, el storage de ClickHouse se multiplicaría por ~2x (360/180), pasando de 71 GB a ~142 GB (mediana) y de 251 GB a ~501 GB (grande) — un incremento marginal frente al storage total de OpenSearch.

| Escenario | Features raw/día | Storage 180d (comprimido) |
|-----------|------------------|---------------------------|
| Mediana | 5.9 GB | **70.8 GB** |
| Grande | 20.9 GB | **250.7 GB** |

### 4.3 Kafka — bus de mensajes transitorio

Kafka retiene mensajes 48 horas con replicación factor 3.

| Escenario | Volumen/día | Storage (48h × 3 réplicas) |
|-----------|-------------|----------------------------|
| Mediana | 118.0 GB | **708 GB** |
| Grande | 417.8 GB | **2.507 GB** |

### 4.4 PCAP — captura de paquetes

PCAP se almacena en almacenamiento dedicado (no OpenSearch). Se asume captura selectiva de headers (no payload completo) para minimizar volumen y riesgo GDPR.

| Escenario | Gbps | PCAP/día | Storage 30d |
|-----------|------|----------|-------------|
| Mediana | 1.5 | 15 GB | **450 GB** |
| Grande | 5.0 | 50 GB | **1.500 GB** |

### 4.5 Resumen de storage total

| Componente | Mediana | Grande |
|-----------|---------|--------|
| OpenSearch hot (SSD) | 6.9 TB | 24.5 TB |
| OpenSearch warm (HDD) | 22.8 TB | 81.3 TB |
| ClickHouse | 0.07 TB | 0.25 TB |
| Kafka | 0.7 TB | 2.5 TB |
| PCAP | 0.4 TB | 1.5 TB |
| **TOTAL SSD** | **~8 TB** | **~27 TB** |
| **TOTAL HDD** | **~23 TB** | **~81 TB** |
| **GRAN TOTAL** | **~31 TB** | **~108 TB** |

> **No incluido en este cálculo**: (1) Tier cold / object storage para datos > 180 días (archive WORM para incidentes y auditoría, 5 años). Este storage es de bajo rendimiento y bajo coste (~0.01 €/GB en NAS o S3 Glacier), y su volumen es pequeño (solo alertas e incidentes, no logs raw). Estimación adicional: ~500 GB–2 TB para 5 años. (2) Snapshot/backup de OpenSearch (recomendado: snapshot diario a NAS/S3, retention 7–30 días, ~1x el tamaño del hot tier).

---

## 5. Requisitos de CPU y RAM

### 5.1 OpenSearch — indexación y búsqueda en tiempo real

#### Dimensionamiento de nodos

OpenSearch requiere tres tipos de nodos: **data** (hot + warm), **master** y opcionalmente **coordinator**. Para KhaiNet se usa el patrón hot/warm/cold:

| Tier | Función | Storage por nodo | RAM por nodo | vCPU por nodo |
|------|---------|------------------|--------------|---------------|
| Hot (SSD) | Indexación + búsquedas recientes (30d) | 2.5–6 TB | 64–128 GB | 8–16 |
| Warm (HDD) | Búsquedas históricas (30–180d) | 6–14 TB | 32–64 GB | 4–8 |
| Master | Gestión de cluster, metadata | 50 GB | 8 GB | 4 |

**Reglas de dimensionamiento aplicadas**:
- **Heap JVM**: 50% de RAM, máximo 31 GB por nodo (recomendación OpenSearch/JVM para evitar compressed oops)
- **Filesystem cache**: 50% de RAM reservada para cache del SO (critical para performance de búsqueda)
- **Shards**: 1 shard por índice diario por ~30–50 GB de datos (evitar shards > 50 GB)
- **Throughput de indexación**: ~1 vCPU por cada 50 GB/día de indexación (con 2x headroom para picos)

#### Asignación por escenario

**Escenario mediana** (indexación: 118 GB/día):

| Rol | Nodos | vCPU/nodo | RAM/nodo | Storage/nodo | Total vCPU | Total RAM |
|-----|-------|-----------|----------|--------------|------------|-----------|
| Hot (SSD) | 3 | 8 | 64 GB | 2.5 TB | 24 | 192 GB |
| Warm (HDD) | 4 | 4 | 32 GB | 6 TB | 16 | 128 GB |
| Master | 3 | 4 | 8 GB | 50 GB | 12 | 24 GB |
| **TOTAL** | **10** | — | — | — | **52** | **344 GB** |

**Escenario grande** (indexación: 418 GB/día):

| Rol | Nodos | vCPU/nodo | RAM/nodo | Storage/nodo | Total vCPU | Total RAM |
|-----|-------|-----------|----------|--------------|------------|-----------|
| Hot (SSD) | 4 | 16 | 128 GB | 6 TB | 64 | 512 GB |
| Warm (HDD) | 6 | 8 | 64 GB | 14 TB | 48 | 384 GB |
| Master | 3 | 4 | 8 GB | 50 GB | 12 | 24 GB |
| **TOTAL** | **13** | — | — | — | **124** | **920 GB** |

### 5.2 Modelos de IA — entrenamiento e inferencia

Los tres modelos base (Isolation Forest, Autoencoder, HMM) tienen requisitos distintos:

| Modelo | Tipo | Entrenamiento | Inferencia | GPU |
|--------|------|---------------|------------|-----|
| Isolation Forest | scikit-learn | CPU-bound, O(n log n), ~5–15 min | <1 ms/evento, CPU | No |
| Autoencoder | PyTorch (denso) | GPU recomendada, 50–100 epochs, ~30–60 min | <5 ms/evento, CPU | Sí (entrenamiento) |
| HMM | hmmlearn | CPU-bound, EM iterations, ~1–5 min | <1 ms/evento, CPU | No |

**Throughput de inferencia**: 1 vCPU procesa ~5.000 eventos/segundo combinando los 3 modelos.

> **Nota sobre el volumen de inferencia**: El cálculo usa solo eventos de Zeek (conn + dns + http + ssl + files + weird) como entrada de los modelos, no el total de logs (Zeek + Suricata + Wazuh). Esto es correcto porque los modelos de anomalías operan sobre metadata de red (Zeek), no sobre alertas de reglas (Suricata) ni logs de endpoint (Wazuh). Suricata y Wazuh alimentan a Brain como alertas pre-filtradas, no a los modelos de ML.

| Escenario | Eventos/s | vCPU inferencia | RAM inferencia | vCPU entrenamiento | RAM entrenamiento | GPU |
|-----------|-----------|-----------------|----------------|---------------------|-------------------|-----|
| Mediana | 1.929 | 1 | 8 GB | 4 | 64 GB | 1× T4 |
| Grande | 6.752 | 2 | 16 GB | 4 | 64 GB | 1× T4 |

> El entrenamiento es batch (semanal/quincenal), no requiere ejecución 24/7. El nodo de entrenamiento puede compartirse con otros workloads fuera de las ventanas de reentrenamiento. La GPU (NVIDIA T4, 16 GB VRAM) solo se usa durante el entrenamiento del Autoencoder.

### 5.3 Otros componentes

| Componente | Escenario | Nodos | vCPU/nodo | RAM/nodo | Storage/nodo |
|-----------|-----------|-------|-----------|----------|--------------|
| **Kafka** (3 brokers, HA) | Mediana | 3 | 4 | 8 GB | 200 GB SSD |
| | Grande | 3 | 8 | 16 GB | 500 GB SSD |
| **ClickHouse** (3 nodos) | Mediana | 3 | 8 | 32 GB | 200 GB SSD |
| | Grande | 3 | 8 | 32 GB | 500 GB SSD |
| **Brain** (LLM KH7) | Ambos | 1 | 8 | 32 GB | 200 GB SSD |
| **SOAR** (Shuffle + TheHive) | Ambos | 1 | 4 | 8 GB | 100 GB SSD |
| **Wazuh Manager** | Mediana | 1 | 4 | 8 GB | 100 GB SSD |
| | Grande | 1 | 8 | 16 GB | 200 GB SSD |
| **Sensores** (Zeek + Suricata) | Mediana | 3 | 8 | 16 GB | 500 GB SSD |
| | Grande | 6 | 16 | 32 GB | 500 GB SSD |

### 5.4 Resumen total de recursos

#### Escenario mediana

| Componente | Nodos | vCPU | RAM (GB) | Storage SSD (GB) | Storage HDD (GB) | GPU |
|-----------|-------|------|----------|-------------------|-------------------|-----|
| OpenSearch Hot | 3 | 24 | 192 | 7.680 | — | — |
| OpenSearch Warm | 4 | 16 | 128 | — | 24.576 | — |
| OpenSearch Master | 3 | 12 | 24 | 150 | — | — |
| Kafka | 3 | 12 | 24 | 600 | — | — |
| ClickHouse | 3 | 24 | 96 | 600 | — | — |
| ML Inferencia | 1 | 1 | 8 | 100 | — | — |
| ML Entrenamiento | 1 | 4 | 64 | 200 | — | 1 |
| Brain (LLM) | 1 | 8 | 32 | 200 | — | — |
| SOAR | 1 | 4 | 8 | 100 | — | — |
| Wazuh Manager | 1 | 4 | 8 | 100 | — | — |
| Sensores | 3 | 24 | 48 | 1.500 | — | — |
| **TOTAL** | **24** | **133** | **632** | **11.230 (11 TB)** | **24.576 (24 TB)** | **1** |

#### Escenario grande

| Componente | Nodos | vCPU | RAM (GB) | Storage SSD (GB) | Storage HDD (GB) | GPU |
|-----------|-------|------|----------|-------------------|-------------------|-----|
| OpenSearch Hot | 4 | 64 | 512 | 24.576 | — | — |
| OpenSearch Warm | 6 | 48 | 384 | — | 86.016 | — |
| OpenSearch Master | 3 | 12 | 24 | 150 | — | — |
| Kafka | 3 | 24 | 48 | 1.500 | — | — |
| ClickHouse | 3 | 24 | 96 | 1.500 | — | — |
| ML Inferencia | 1 | 2 | 16 | 100 | — | — |
| ML Entrenamiento | 1 | 4 | 64 | 200 | — | 1 |
| Brain (LLM) | 1 | 8 | 32 | 200 | — | — |
| SOAR | 1 | 4 | 8 | 100 | — | — |
| Wazuh Manager | 1 | 8 | 16 | 200 | — | — |
| Sensores | 6 | 96 | 192 | 3.000 | — | — |
| **TOTAL** | **30** | **294** | **1.392** | **31.526 (31 TB)** | **86.016 (84 TB)** | **1** |

---

## 6. Estimación de costes

### 6.1 Coste on-premise (Proxmox VE)

#### Supuestos de hardware

| Componente | Precio unitario | Justificación |
|-----------|----------------|---------------|
| Servidor 2U (32 vCPU, 256 GB RAM, 8 bahías) | 12.000 € | Intel Xeon Silver/Gold dual-socket, 256 GB DDR4 ECC |
| Servidor 4U (64 vCPU, 512 GB RAM, 24 bahías) | 25.000 € | Intel Xeon Gold/Platinum dual-socket, 512 GB DDR4 ECC |
| SSD enterprise SATA (por GB) | 0,12 €/GB | SSD datacenter 1–4 TB |
| HDD enterprise (por GB) | 0,025 €/GB | HDD NAS/datacenter 8–16 TB |
| GPU NVIDIA T4 (16 GB VRAM) | 1.200 € | GPU para entrenamiento de Autoencoder |
| Proxmox VE Enterprise Subscription | 200 €/año/servidor | Soporte oficial Proxmox |

#### Costes operativos

| Concepto | Valor | Justificación |
|----------|-------|---------------|
| Amortización hardware | 48 meses (4 años) | Vida útil estimada del servidor |
| Electricidad | 0,15 €/kWh, 500 W por servidor | Consumo promedio bajo carga |
| Mantenimiento | 10% del hardware/año | Soporte hardware, recambios, actualizaciones |

#### Resultado on-premise — escenario mediana

| Concepto | Cálculo | Coste |
|----------|---------|-------|
| Servidores físicos | 6 × 12.000 € | 72.000 € |
| SSD (11 TB) | 11.230 × 0,12 € | 1.348 € |
| HDD (24 TB) | 24.576 × 0,025 € | 614 € |
| GPU (1× T4) | 1 × 1.200 € | 1.200 € |
| **TOTAL hardware** | | **75.162 €** |
| Amortización mensual | 75.162 / 48 | 1.566 €/mes |
| Electricidad mensual | 6 × 0,5 kW × 24h × 30d × 0,15 € | 324 €/mes |
| Mantenimiento mensual | (75.162 × 10%) / 12 | 626 €/mes |
| Proxmox mensual | (6 × 200 €) / 12 | 100 €/mes |
| **TOTAL mensual** | | **2.616 €/mes** |
| **TOTAL anual** | | **31.395 €/año** |

#### Resultado on-premise — escenario grande

| Concepto | Cálculo | Coste |
|----------|---------|-------|
| Servidores físicos | 6 × 25.000 € | 150.000 € |
| SSD (31 TB) | 31.526 × 0,12 € | 3.783 € |
| HDD (84 TB) | 86.016 × 0,025 € | 2.150 € |
| GPU (1× T4) | 1 × 1.200 € | 1.200 € |
| **TOTAL hardware** | | **157.134 €** |
| Amortización mensual | 157.134 / 48 | 3.274 €/mes |
| Electricidad mensual | 6 × 0,5 kW × 24h × 30d × 0,15 € | 324 €/mes |
| Mantenimiento mensual | (157.134 × 10%) / 12 | 1.309 €/mes |
| Proxmox mensual | (6 × 200 €) / 12 | 100 €/mes |
| **TOTAL mensual** | | **5.007 €/mes** |
| **TOTAL anual** | | **60.085 €/año** |

> **Nota sobre número de servidores**: El dimensionamiento por CPU requiere 6 servidores para ambos escenarios (evitando sobresuscripción de CPU). El storage warm (HDD) se distribuye en servidores con bahías para discos grandes (16 TB). Una alternativa es usar **NAS/NFS dedicado** para el tier warm de OpenSearch, lo que reduciría el número de servidores compute pero añadiría un dispositivo de storage dedicado. Esta opción debe evaluarse en la fase de despliegue según disponibilidad de hardware y presupuesto.

### 6.2 Coste cloud (AWS como referencia)

#### Supuestos cloud

| Recurso | Precio (3-year reservation) | Justificación |
|---------|-----------------------------|---------------|
| r5.4xlarge (16 vCPU, 128 GB RAM) | 400 €/mes | Memory-optimized para OpenSearch/ClickHouse |
| EBS gp3 (SSD) | 0,08 €/GB/mes | General purpose SSD |
| EBS st1 (HDD) | 0,025 €/GB/mes | Throughput-optimized HDD |
| GPU T4 (g4dn.xlarge) | 360 €/mes | GPU instance para entrenamiento |
| Data transfer | 50 €/mes | Estimación 1 TB outbound/mes |

#### Resultado cloud

> **Mapeo de nodos a instancias**: Los 24 VMs (mediana) / 30 VMs (grande) se consolidan en instancias r5.4xlarge (16 vCPU / 128 GB RAM) agrupando múltiples VMs por instancia, ya que la mayoría de componentes (Kafka, ClickHouse, Brain, SOAR, Wazuh, ML) tienen requisitos modestos que caben varias por instancia. Los nodos Hot de OpenSearch requieren instancias dedicadas o storage-optimized (i3) por su alto uso de RAM y SSD. El cálculo siguiente es una estimación simplificada; un dimensionamiento cloud detallado requeriría mapear cada VM al tipo de instancia óptimo.

| Concepto | Mediana | Grande |
|----------|---------|--------|
| Compute (r5.4xlarge) | 9 instancias × 400 € = 3.600 €/mes | 19 instancias × 400 € = 7.600 €/mes |
| SSD (EBS gp3) | 11.230 × 0,08 = 898 €/mes | 31.526 × 0,08 = 2.522 €/mes |
| HDD (EBS st1) | 24.576 × 0,025 = 614 €/mes | 86.016 × 0,025 = 2.150 €/mes |
| GPU | 360 €/mes | 360 €/mes |
| Network | 50 €/mes | 50 €/mes |
| **TOTAL mensual** | **5.523 €/mes** | **12.682 €/mes** |
| **TOTAL anual** | **66.274 €/año** | **152.190 €/año** |

> **Nota**: El coste cloud es 2.5–3x más caro que on-premise, principalmente por el coste de EBS storage (SSD + HDD) que se paga mensualmente de forma recurrente. Con 3-year reservation se obtiene ~40% de descuento vs on-demand. Sin reservation, el coste sería ~1.7x mayor.

### 6.3 Coste de personal (TCO real)

El coste de infraestructura es solo una parte del TCO. KhaiNet requiere talento interno que Darktrace incluye (parcialmente) en su licencia:

| Rol | FTE | Coste anual estimado | Justificación |
|-----|-----|---------------------|---------------|
| Ingeniero de red / NDR | 1 | 60.000 € | Configuración de Zeek, Suricata, SPAN, sensores |
| Ingeniero de ML / Data | 1 | 70.000 € | Modelos, feature engineering, MLflow, drift detection |
| Analista SOC (compartido) | 0,5 | 35.000 € | Respuesta a incidentes, tuning de alertas, feedback |
| **TOTAL personal** | **2,5 FTE** | **165.000 €/año** | |

> **Nota**: Estos roles pueden ser parcialmente compartidos con el equipo existente de ciberseguridad. Si la organización ya tiene un SOC y ingenieros de red, el coste incremental puede ser menor (0,5–1 FTE adicional). Darktrace reduce esta necesidad pero no la elimina: se necesita personal para gestionar la consola, investigar alertas y mantener reglas.

### 6.4 TCO comparativo (3 años)

| Concepto | Darktrace (mediana) | KhaiNet on-prem (mediana) | KhaiNet cloud (mediana) |
|----------|--------------------|---------------------------|-------------------------|
| Licencia / hardware (año 0) | 0 € | 75.162 € | 0 € |
| Coste anual recurrento | 420.000 € | 31.395 € + 165.000 € personal = 196.395 € | 66.274 € + 165.000 € = 231.274 € |
| **TCO 3 años** | **1.260.000 €** | **75.162 + 3×196.395 = 664.347 €** | **3×231.274 = 693.822 €** |
| **Ahorro 3 años** | — | **595.653 € (47%)** | **566.178 € (45%)** |

| Concepto | Darktrace (grande) | KhaiNet on-prem (grande) | KhaiNet cloud (grande) |
|----------|--------------------|---------------------------|-------------------------|
| Licencia / hardware (año 0) | 0 € | 157.134 € | 0 € |
| Coste anual recurrento | 896.000 € | 60.085 € + 165.000 € = 225.085 € | 152.190 € + 165.000 € = 317.190 € |
| **TCO 3 años** | **2.688.000 €** | **157.134 + 3×225.085 = 832.389 €** | **3×317.190 = 951.570 €** |
| **Ahorro 3 años** | — | **1.855.611 € (69%)** | **1.736.430 € (65%)** |

> **Conclusión TCO**: Incluso contabilizando el coste de personal (2,5 FTE), KhaiNet on-premise ofrece un **ahorro del 47–69%** sobre Darktrace a 3 años. El ahorro es mayor en organizaciones grandes porque el coste de licencia de Darktrace escala linealmente con el número de sensores, mientras que el coste de infraestructura de KhaiNet escala sublinealmente (economías de escala en hardware). El coste de personal es idéntico en ambos escenarios (2,5 FTE); en la práctica, el escenario grande puede requerir 0,5–1 FTE adicional (más sensores, más tuning, más alertas), pero esto no altera significativamente el ROI.

---

## 7. Comparación con coste de licencia Darktrace

### 7.1 Modelo de pricing de Darktrace

Darktrace cobra por **sensor (appliance)** más módulos opcionales:

| Componente | Modelo de pricing | Coste estimado |
|-----------|-------------------|----------------|
| Darktrace Immune System (base) | Per sensor/año | 50.000–80.000 € |
| Antigena (respuesta automatizada) | +30–50% del base | +40% (estimado) |
| Darktrace Pro (threat intel) | +10–20% del base | No incluido en esta estimación |
| Darktrace Cloud (monitorización cloud) | Per sensor adicional | No incluido |

> **Fuentes**: Gartner Peer Insights, reviews públicas, RFP leaks. Los precios reales varían significativamente según negociación, región y tamaño del despliegue. Estos son rangos conservadores.

### 7.2 Estimación por escenario

| Escenario | Sensores | Coste base/sensor | Base anual | Antigena (+40%) | **Total anual** |
|-----------|----------|-------------------|------------|------------------|-----------------|
| Mediana | 4 | 75.000 € | 300.000 € | 120.000 € | **420.000 €** |
| Grande | 8 | 80.000 € | 640.000 € | 256.000 € | **896.000 €** |

### 7.3 Comparación directa

| Métrica | Mediana | Grande |
|---------|---------|--------|
| Darktrace anual | 420.000 € | 896.000 € |
| KhaiNet on-premise anual (solo infra) | 31.395 € | 60.085 € |
| KhaiNet cloud anual (solo infra) | 66.274 € | 152.190 € |
| **ROI on-premise (solo infra)** | **13x** | **15x** |
| **ROI cloud (solo infra)** | **6x** | **6x** |
| Ahorro on-premise (solo infra) | 388.605 €/año (92%) | 835.915 €/año (93%) |
| Ahorro cloud (solo infra) | 353.726 €/año (84%) | 743.810 €/año (83%) |
| **TCO on-premise con personal (3 años)** | 664.347 € | 832.389 € |
| **TCO Darktrace (3 años)** | 1.260.000 € | 2.688.000 € |
| **Ahorro TCO 3 años** | 595.653 € (47%) | 1.855.611 € (69%) |

---

## 8. Recomendación de asignación de recursos

### 8.1 Arquitectura de despliegue recomendada (Proxmox VE)

#### Escenario mediana — 6 servidores físicos (2U)

| Servidor | VMs alojadas | vCPU | RAM | Storage | Headroom |
|----------|-------------|------|-----|---------|----------|
| **SRV-01** (2U, 32 vCPU, 256 GB) | 3× OpenSearch Hot | 24 | 192 GB | 7.5 TB SSD | 25% CPU, 25% RAM |
| **SRV-02** (2U, 32 vCPU, 256 GB) | 2× OpenSearch Warm + 1× Master | 12 | 72 GB | 12 TB HDD + 50 GB SSD | 63% CPU, 72% RAM |
| **SRV-03** (2U, 32 vCPU, 256 GB) | 2× OpenSearch Warm + 1× Kafka | 12 | 72 GB | 12 TB HDD + 200 GB SSD | 63% CPU, 72% RAM |
| **SRV-04** (2U, 32 vCPU, 256 GB) | 1× Kafka + 2× ClickHouse + Brain + SOAR | 32 | 112 GB | 900 GB SSD | 0% CPU, 56% RAM |
| **SRV-05** (2U, 32 vCPU, 256 GB) | 1× ClickHouse + Wazuh + ML Inf + ML Train (GPU) + 1× Sensor | 25 | 128 GB | 1.1 TB SSD + GPU T4 | 22% CPU, 50% RAM |
| **SRV-06** (2U, 32 vCPU, 256 GB) | 2× Sensores + 2× Master + 1× Kafka | 28 | 56 GB | 1.3 TB SSD | 13% CPU, 78% RAM |
| **TOTAL** | **24 VMs** | **133** | **632 GB** | **11 TB SSD + 24 TB HDD** | — |

> **Nota SRV-04**: Este servidor utiliza el 100% de los vCPU físicos (32/32). En Proxmox, esto es viable porque no todas las VMs pican simultáneamente: Brain y SOAR tienen cargas bursty, mientras que Kafka y ClickHouse son más estables. Si se prefiere mayor headroom, se puede mover 1× ClickHouse a SRV-05 (que tiene 22% de headroom) y reducir SRV-04 a 24 vCPU.

#### Escenario grande — 6 servidores físicos (4U)

| Servidor | VMs alojadas | vCPU | RAM | Storage | Headroom |
|----------|-------------|------|-----|---------|----------|
| **SRV-01** (4U, 64 vCPU, 512 GB) | 4× OpenSearch Hot | 64 | 512 GB | 24 TB SSD | 0% CPU, 0% RAM |
| **SRV-02** (4U, 64 vCPU, 512 GB) | 3× OpenSearch Warm + 1× Master | 28 | 200 GB | 42 TB HDD + 50 GB SSD | 56% CPU, 61% RAM |
| **SRV-03** (4U, 64 vCPU, 512 GB) | 3× OpenSearch Warm + 1× Kafka | 32 | 208 GB | 42 TB HDD + 500 GB SSD | 50% CPU, 59% RAM |
| **SRV-04** (4U, 64 vCPU, 512 GB) | 2× Kafka + 3× ClickHouse + Brain + SOAR + Wazuh + ML Inf | 62 | 200 GB | 3.1 TB SSD | 3% CPU, 61% RAM |
| **SRV-05** (4U, 64 vCPU, 512 GB) | 3× Sensores + ML Train (GPU) | 52 | 160 GB | 1.7 TB SSD + GPU T4 | 19% CPU, 69% RAM |
| **SRV-06** (4U, 64 vCPU, 512 GB) | 3× Sensores + 2× Master | 56 | 112 GB | 1.6 TB SSD | 13% CPU, 78% RAM |
| **TOTAL** | **30 VMs** | **294** | **1.392 GB** | **31 TB SSD + 84 TB HDD** | — |

> **Nota SRV-01**: Este servidor utiliza el 100% de vCPU y RAM físicos (64/64, 512/512). Los nodos Hot de OpenSearch son los más demandantes. Si se prefiere headroom, se puede dividir en 2 servidores (2× Hot por servidor, 32 vCPU / 256 GB cada uno), aumentando el total a 7 servidores. Alternativamente, se puede reducir a 3 nodos Hot (48 vCPU / 384 GB) aceptando menos throughput de indexación.

> **Asignación orientativa**: En la práctica, Proxmox permite ajustar dinámicamente vCPU y RAM según carga, y la sobresuscripción de CPU es viable cuando las VMs no pican simultáneamente. Se recomienda monitorizar la carga real tras el despliegue y reequilibrar VMs si algún servidor supera el 80% de uso sostenido.

### 8.2 Recomendaciones de optimización

1. **Tiering hot/warm/cold en OpenSearch**: Esencial para contener costes. Los datos calientes (30 días) en SSD para búsquedas rápidas; los datos templados (30–180 días) en HDD para almacenamiento económico. Configurar ISM policies (ya definidas en `docs/compliance-gobernanza.md`).

2. **Optimización de Suricata**: Configurar eve.json para emitir solo alertas + flow start/end (no todos los eventos de protocolo). Esto reduce el volumen de Suricata en ~80%, pasando de 67 GB/día a ~14 GB/día (mediana). El trade-off es perder metadata detallada de protocolos, pero Zeek ya captura esa información.

3. **Compresión ZSTD en OpenSearch**: Cambiar la compresión por defecto (LZ4) a ZSTD para logs. Esto reduce el storage en ~15-20% adicional. Configurar `index.codec: best_compression` en los templates de índice.

4. **Réplicas ajustables**: Para índices warm/cold (datos > 30 días), considerar reducir réplicas a 0 si se usa snapshot/restore como mecanismo de HA. Esto reduce el storage a la mitad para datos históricos.

5. **Kafka retention corta**: 48 horas es suficiente como buffer. No ampliar más — Kafka es transitorio por diseño (definido en compliance).

6. **ClickHouse para analytics pesados**: Mover agregaciones y feature engineering a ClickHouse reduce la carga en OpenSearch. ClickHouse es 10–100x más rápido en agregaciones temporales.

7. **GPU compartida**: La GPU T4 solo se usa durante el entrenamiento del Autoencoder (semanal/quincenal, 30–60 min). Fuera de esas ventanas, puede usarse para otros workloads o compartirse vía vGPU.

### 8.3 Escalado horizontal

La arquitectura está diseñada para escalar horizontalmente:

| Componente | Escalado | Acción |
|-----------|----------|--------|
| OpenSearch Hot | Añadir nodos data hot | +1 nodo = +2.5–6 TB SSD + 8–16 vCPU |
| OpenSearch Warm | Añadir nodos data warm | +1 nodo = +6–14 TB HDD + 4–8 vCPU |
| Kafka | Añadir brokers | +1 broker = +200–500 GB SSD + 4–8 vCPU |
| ClickHouse | Añadir shards | +1 nodo = +200–500 GB SSD + 8 vCPU |
| Sensores | Añadir sensores | +1 sensor por segmento de red |
| ML Inferencia | Añadir nodos ML | +1 nodo = +1–2 vCPU + 8–16 GB RAM |

---

## 9. Riesgos y mitigaciones del dimensionamiento

| # | Riesgo | Impacto | Probabilidad | Mitigación |
|---|--------|---------|--------------|------------|
| 1 | **Volumen real de tráfico mayor al estimado** | Storage insuficiente | Media | Captura piloto de 1 semana antes de comprar hardware. Los benchmarks asumen tráfico "normal"; picos o tráfico inusual pueden duplicar el volumen. |
| 2 | **Suricata genera más eventos de los esperados** | Storage y CPU insuficientes | Media | Configurar Suricata para emitir solo alertas + flow events. Monitorizar volumen real y ajustar. |
| 3 | **OpenSearch hot nodes saturados por búsquedas del SOC** | Degradación de performance | Media | Añadir nodos coordinator dedicados si las búsquedas son frecuentes. Monitorizar query latency y thread pool queue. |
| 4 | **Discos HDD warm lentos para búsquedas retrospectivas** | Lentitud en investigaciones | Baja | Para investigaciones que requieren datos > 30 días, usar snapshots a S3/NAS y restaurar bajo demanda. |
| 5 | **Coste de personal subestimado** | TCO mayor al previsto | Alta | El coste de 2,5 FTE es conservador. Si la organización no tiene equipo existente, puede ser 3–4 FTE. Considerar servicios gestionados (MSSP) como alternativa. |
| 6 | **Precio de Darktrace negociado menor al estimado** | ROI menor al previsto | Baja | Los precios de Darktrace son rangos conservadores. Algunas organizaciones obtienen descuentos del 30–50% en renewals. Recalcular ROI con el precio real de la organización. |
| 7 | **Hardware no disponible o con retrasos** | Retraso en despliegue | Baja | Considerar cloud como fallback temporal. Usar servidores refurbished para reducir coste y tiempo de entrega. |

---

## 10. Validación recomendada antes de comprometer hardware

Antes de comprar el hardware definitivo, se recomienda:

1. **Captura piloto (1 semana)**: Desplegar 1 sensor Zeek + Suricata en el segmento de mayor tráfico. Medir:
   - Eventos/día reales por tipo de log
   - Volumen real en GB/día
   - Picos de tráfico y eventos/segundo
   - Comparar con las estimaciones de este documento

2. **Ajustar fórmulas**: Con los datos reales del piloto, recalcular storage, CPU y RAM usando las mismas fórmulas de este documento.

3. **Proof of concept OpenSearch**: Desplegar OpenSearch en una VM con 50–100 GB de logs reales. Medir:
   - Ratio de compresión real (ZSTD vs LZ4)
   - Throughput de indexación
   - Latencia de búsquedas
   - Overhead real del índice invertido

4. **Validar coste de Darktrace**: Obtener el precio real de la licencia actual de Darktrace (o el quote de renewal) para recalcular el ROI con datos precisos.

---

## 11. Conclusión

El estudio confirma que el coste de infraestructura de OpenSearch estaba **subestimado en la propuesta original** (Riesgo #3), pero el dimensionamiento corregido sigue siendo **marginal frente al coste de Darktrace**:

- **Infraestructura on-premise**: 31.000–60.000 €/año (mediana–grande)
- **Licencia Darktrace**: 420.000–896.000 €/año (mediana–grande)
- **ROI solo infraestructura**: 13x–15x (on-premise), 6x (cloud)
- **TCO con personal (3 años)**: ahorro del 47–69% vs Darktrace

La recomendación es desplegar en **Proxmox VE on-premise** con tiering hot/warm/cold, priorizando la contratación de talento interno (ingeniero de red + ingeniero de ML) como factor crítico de éxito. El hardware es el menor de los costes; el conocimiento y la capacidad de operación son el verdadero diferencial.

### Próximos pasos

1. Validar estimaciones con captura piloto de 1 semana
2. Obtener precio real de Darktrace para recalcular ROI
3. Desplegar infraestructura core (issue en backlog: "Desplegar infraestructura core")
4. Ajustar dimensionamiento con datos reales tras 30 días de operación

---

## Apéndice A — Fórmulas de cálculo

### Volumen de logs

```
eventos_zeek_total = conexiones_conn_log / 0.60  (conn es 60% del total)
volumen_zeek = Σ (eventos_tipo × bytes_por_evento_tipo)

eventos_suricata = conexiones_conn_log × 1.2
volumen_suricata = eventos_suricata × 600 bytes

volumen_wazuh = agentes × 10 MB/día × 1.10 (overhead manager)
```

### Storage OpenSearch

```
storage_raw = Σ (volumen_diario × días_retención_por_componente)
storage_opensearch = storage_raw × 1.955  (ZSTD 0.85 × réplicas 2 × overhead 1.15)
```

### CPU OpenSearch

```
cpu_indexacion = ceil(volumen_diario_GB / 50) × 2  (1 vCPU por 50 GB/día, 2x headroom)
nodos_data = max(3, ceil(storage_180d / max_storage_por_nodo))
```

### CPU modelos IA

```
eventos_por_segundo = eventos_zeek_día / 86400
cpu_inferencia = ceil(eventos_por_segundo / 5000)  (5000 ev/s por vCPU)
```

### Coste on-premise

```
coste_hardware = servidores × precio + SSD_GB × 0.12 + HDD_GB × 0.025 + GPU × 1200
coste_mensual = (coste_hardware / 48) + electricidad + (coste_hardware × 0.10 / 12) + proxmox
electricidad = num_servidores × 0.5 kW × 24h × 30d × 0.15 €/kWh
proxmox = num_servidores × 200 € / 12
```

---

## Apéndice B — Parámetros ajustables

Los siguientes parámetros pueden ajustarse según las condiciones reales de la organización:

| Parámetro | Valor usado | Rango razonable | Impacto |
|-----------|-------------|-----------------|---------|
| Conexiones/día por Gbps | 67M (mediana), 70M (grande) | 50–100M | ±50% storage |
| Bytes por evento Zeek conn | 300 | 200–400 | ±33% volumen Zeek |
| Bytes por evento Suricata | 600 | 400–800 | ±33% volumen Suricata |
| Compresión OpenSearch | 0.85 (ZSTD) | 0.70–0.95 | ±15% storage |
| Réplicas OpenSearch | 1 (2 copias) | 0–1 | ±50% storage |
| MB/día por agente Wazuh | 10 | 5–20 | ±50% volumen Wazuh |
| Eventos/s por vCPU ML | 5.000 | 3.000–10.000 | ±40% CPU ML |
| Coste servidor 2U | 12.000 € | 8.000–15.000 € | ±25% coste hardware |
| Coste servidor 4U | 25.000 € | 18.000–30.000 € | ±20% coste hardware |
| Precio Darktrace/sensor | 75.000–80.000 € | 50.000–100.000 € | ±33% ROI |

---

*Documento de dimensionamiento KhaiNet · Versión 1.0 · 2026-07-03*
*Mantenido por el equipo KhaiNet (Grupo Khlloreda / KH7)*
