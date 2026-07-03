# Cumplimiento, Gobernanza y Roles — KhaiNet

> **Documento de cumplimiento — Proyecto KhaiNet**
> Fecha: 2026-07-03
> Estado: Borrador v1 (pendiente de revisión por DPO y CISO)
> Vinculado a: [Arquitectura KhaiNet](darktrace-alternativa-software-libre.md) — Sección 13 (Riesgos, #9)

---

## Tabla de contenidos

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Análisis GDPR: datos personales en logs de red](#2-análisis-gdpr-datos-personales-en-logs-de-red)
3. [Política de retención de datos](#3-política-de-retención-de-datos)
4. [Seudonimización y anonimización de IPs](#4-seudonimización-y-anonimización-de-ips)
5. [Gobernanza de detección y respuesta](#5-gobernanza-de-detección-y-respuesta)
6. [Roles y responsabilidades](#6-roles-y-responsabilidades)
7. [Cadena de custodia digital](#7-cadena-de-custodia-digital)
8. [Notificación de brechas (Art. 33-34 GDPR)](#8-notificación-de-brechas-art-33-34-gdpr)
9. [DPIA — Evaluación de Impacto en Protección de Datos](#9-dpia--evaluación-de-impacto-en-protección-de-datos)
10. [Checklist de implementación](#10-checklist-de-implementación)
11. [Referencias normativas](#11-referencias-normativas)

---

## 1. Resumen ejecutivo

KhaiNet es una plataforma de detección y respuesta a amenazas de red (NDR) que captura,
analiza y almacena tráfico de red a escala organizacional. Esta actividad constituye un
**tratamiento de datos personales a gran escala y de forma habitual y sistemática** bajo
el Reglamento General de Protección de Datos (GDPR / RGPD), lo que exige:

- **Base jurídica** documentada (interés legítimo, Art. 6(1)(f))
- **Evaluación de Impacto (DPIA)** obligatoria (Art. 35)
- **Designación de DPO** obligatoria (Art. 37(1)(b))
- **Medidas técnicas y organizativas** de protección por diseño y por defecto (Art. 25, Art. 32)
- **Política de retención** con plazos definidos y eliminación automática (Art. 5(1)(e))
- **Seudonimización** de identificadores personales (IPs) en operaciones rutinarias (Art. 25, Art. 32)
- **Gobernanza formal** de reglas de detección y respuestas automatizadas
- **Cadena de custodia** para evidencias digitales (ISO 27037)

Este documento define las políticas, procedimientos y configuraciones técnicas para
cumplir estos requisitos en el contexto del stack KhaiNet: **Zeek**, **Suricata**,
**Wazuh**, **OpenSearch**, **Shuffle** y **Brain**.

---

## 2. Análisis GDPR: datos personales en logs de red

### 2.1 ¿Las direcciones IP son datos personales?

**Sí.** Las direcciones IP —tanto estáticas como dinámicas— se consideran datos personales
bajo el GDPR cuando pueden utilizarse para identificar a una persona física, directa o
indirectamente.

**Jurisprudencia clave:**
- **Sentencia CJUE C-582/14 (Breyer vs. Alemania, 19 octubre 2016):** El Tribunal de
  Justicia de la UE estableció que una dirección IP dinámica constituye un dato personal
  para un proveedor de servicios cuando este dispone de los medios legales (como una orden
  judicial) que permiten identificar al usuario asociado. El criterio es la **posibilidad
  razonable** de identificación, no que el responsable tenga ya la información.
- **Considerando 30 del GDPR:** Establece explícitamente que las personas físicas pueden
  ser asociadas con identificadores en línea, **"tales como direcciones de protocolo de
  internet (IP), identificadores de cookies u otros identificadores"**.

**Conclusión para KhaiNet:** Todas las IPs capturadas por Zeek/Suricata —tanto de origen
como de destino, internas y externas— deben tratarse como datos personales a efectos del
GDPR.

### 2.2 Inventario de datos personales en logs de red

| Metadato | Componente que lo genera | ¿Dato personal? | Base normativa |
|----------|-------------------------|-----------------|----------------|
| Direcciones IP (src/dst) | Zeek (conn.log), Suricata (eve.json) | ✅ Sí | CJUE C-582/14; Cons. 30 |
| Direcciones MAC | Zeek (conn.log) | ✅ Sí | Identificador único de hardware |
| Consultas DNS | Zeek (dns.log) | ✅ Sí | Revelan comportamiento e intereses; Cons. 30 |
| URLs visitadas | Zeek (http.log) | ✅ Sí | Datos de localización/comportamiento |
| User-Agents HTTP | Zeek (http.log) | ✅ Sí | Fingerprinting de dispositivo |
| Payloads HTTP | Zeek (http.log, files.log) | ✅ Sí (potencialmente Art. 9) | Pueden contener credenciales, datos sensibles |
| Certificados SSL/TLS (CN/SAN) | Zeek (ssl.log) | ✅ Sí | Revelan dominios visitados |
| Tiempos de conexión | Zeek (conn.log) | ✅ Sí | Patrones temporales de actividad |
| Volúmenes de tráfico | Zeek (conn.log) | ⚠️ Contextual | Combinados con IP/timestamp sí lo son |
| Logs de host (auth, syslog) | Wazuh | ✅ Sí | Contienen usernames, comandos, IPs |
| Alertas de Suricata | Suricata (eve.json) | ✅ Sí | Incluyen IPs, payloads, metadatos |
| Correlaciones de Brain | Brain (output) | ✅ Sí | Hereda datos personales de las alertas de entrada |

### 2.3 Base jurídica: interés legítimo (Art. 6(1)(f))

El tratamiento de datos de red con fines de ciberseguridad se basa en el **interés
legítimo** del responsable del tratamiento en proteger sus sistemas, redes y datos.

**Fundamento normativo:**
- **Considerando 49 del GDPR:** "El tratamiento de datos personales en la medida
  estrictamente necesaria y proporcionada para garantizar la seguridad de las redes y la
  información" puede constituir un interés legítimo. Esto incluye "prevenir el acceso no
  autorizado a redes electrónicas de comunicaciones y la distribución maliciosa de código"
  y "daños a sistemas informáticos o de comunicaciones electrónicas."

**Por qué no otras bases:**
- **Consentimiento (Art. 6(1)(a)):** Inadecuado por desequilibrio de poder
  (empleado-empleador) y dificultad de retirada.
- **Obligación legal (Art. 6(1)(c)):** Solo si existe normativa nacional que obligue a
  monitorizar; limita flexibilidad.
- **Ejecución de contrato (Art. 6(1)(b)):** Insuficiente para seguridad general.

### 2.4 Evaluación de Interés Legítimo (LIA)

El Art. 6(1)(f) requiere un **test de tres partes** que debe documentarse formalmente:

#### Test 1: Necesidad

La monitorización NDR es necesaria para detectar intrusiones, malware, exfiltración de
datos, comunicaciones C2, y movimientos laterales. No existe alternativa menos intrusiva
que proporcione el mismo nivel de detección.

**Casos de uso cubiertos:**
- Detección de anomalías de tráfico (Isolation Forest, Autoencoders, HMM)
- Detección por firmas (Suricata + ET-Open)
- Correlación de incidentes (Brain)
- Respuesta automatizada (Shuffle)

#### Test 2: Proporcionalidad / Balance de intereses

| Factor | Evaluación |
|--------|-----------|
| Naturaleza de la relación | Empleados en infraestructura corporativa (menor expectativa de privacidad que en comunicaciones personales) |
| Tipo de datos | Metadatos de red por defecto (menos sensibles); payloads solo en investigación de incidentes |
| Impacto en el interesado | Bajo si se aplican salvaguardias (seudonimización, acceso restringido, retención limitada) |
| Salvaguardas implementadas | Seudonimización de IPs, RBAC, retención automática, prohibición de uso para vigilancia laboral |

#### Test 3: Salvaguardas del interesado

- Seudonimización de IPs en operaciones rutinarias (ver sección 4)
- Acceso restringido por roles (RBAC en OpenSearch)
- Política de retención con eliminación automática (ver sección 3)
- **Prohibición expresa** de usar datos de red para vigilancia laboral o fines no de seguridad
- Transparencia: información a empleados y usuarios (Art. 13/14) sobre la monitorización

> **Requisito:** La LIA debe documentarse formalmente, ser aprobada por el DPO y revisarse
> anualmente o cuando cambien los casos de uso.

### 2.5 Principio de minimización de datos (Art. 5(1)(c))

Los datos deben ser "adecuados, pertinentes y limitados a lo necesario en relación con los
fines para los que son tratados."

**Aplicación por componente:**

| Componente | Medida de minimización |
|-----------|----------------------|
| **Zeek** | Configurar `local.nets` para distinguir tráfico interno/externo. Deshabilitar loggers innecesarios. No registrar payloads completos por defecto. Usar `LogAscii::use_json=T` para facilitar filtrado. |
| **Suricata** | Configurar `eve.json` excluyendo campos innecesarios. `payload-printable` solo para alertas, no para todo el tráfico. |
| **Wazuh** | Filtrar logs en el agente antes de enviar al servidor. `localfile` selectivo. `syscheck` excluyendo rutas con datos personales innecesarios. |
| **OpenSearch** | Ingest pipelines para seudonimizar IPs en tiempo de indexación. ILM para eliminación automática. |
| **Shuffle** | Limitar datos pasados entre nodos del workflow. No incluir payloads completos en notificaciones (Slack/email). |
| **Brain** | Recibe alertas pre-filtradas, no tráfico bruto. No persistir datos personales más allá del ciclo de correlación. |

**Principio clave:** Si Zeek genera logs de conexión (conn.log) suficientes para detección,
no habilitar captura de payloads HTTP completos salvo para investigación de incidentes
específicos con autorización.

---

## 3. Política de retención de datos

### 3.1 Marco normativo

- **Art. 5(1)(e) GDPR:** Los datos personales deben "conservarse de forma que permita la
  identificación de los interesados durante no más tiempo del necesario."
- **Art. 25 GDPR:** La retención mínima debe configurarse por defecto (privacidad por diseño).
- **ISO/IEC 27001:2022 — Control A.8.10 (Information deletion):** Requiere políticas y
  procedimientos para la eliminación de información. **Control A.8.3 (Information storage):**
  Requiere definir y aplicar reglas de almacenamiento de información.
- **ENISA Handbook on Security of Personal Data Processing (2018):** Períodos basados en
  riesgo y necesidad operativa, documentando justificación.

### 3.2 Tabla de retención

| Tipo de dato | Hot (indexación activa) | Warm (read-only) | Eliminación |
|-------------|------------------------|-------------------|-------------|
| **Logs de red Zeek** (conn.log, dns.log, http.log, ssl.log) | 0-30 días | 30-180 días | **180 días** |
| **Alertas Suricata** (eve.json alerts) | 0-90 días | 90-365 días | **365 días** |
| **Logs Wazuh** (syslog, auth, syscheck) | 0-90 días | 90-365 días | **365 días** |
| **Incidentes confirmados / casos** | 0-365 días | 1-3 años (archive) | **5 años** (si hay litigio) |
| **PCAP completo** (captura de paquetes) | 0-7 días (rotación) | — | **30 días** (salvo incidente) |
| **Evidencias forenses** (incidentes) | — | WORM (read-only) | **Mín. 3 años** |
| **Logs de auditoría SOC** (quién accedió a qué) | 0-365 días | 1-5 años | **5 años** |
| **Modelos IA** (Brain, anomalías) | — | — | **Permanente** (sin datos personales) |
| **Alertas de Brain** (correlaciones) | 0-90 días | 90-365 días | **365 días** |

**Justificación de plazos:**
- **30 días hot para Zeek:** Cubre la mayoría de investigaciones retrospectivas inmediatas.
- **180 días total para Zeek:** Cubre detección de campañas APT de duración media (dwell
  time media 10-200 días según MTTD reports). Balance entre necesidad de seguridad y
  minimización.
- **PCAP 7-30 días:** El PCAP contiene el máximo de datos personales (payloads completos).
  Retención corta por defecto; extensión solo bajo investigación activa autorizada.
- **Incidentes 5 años:** Soporte de acciones legales, seguros, y obligaciones de retención
  nacional.
- **Logs de auditoría 5 años:** Trazabilidad de accesos a datos personales para
  demostrar cumplimiento ante la autoridad.

### 3.3 Implementación en OpenSearch (ISM — Index State Management)

#### Política de retención para logs de Zeek (180 días)

```json
PUT _plugins/_ism/policies/zeek-retention-180d
{
  "policy": {
    "description": "Retention policy for Zeek logs — hot 30d, warm 30d-180d, delete at 180d",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          { "rollover": { "min_size": "50gb", "min_doc_count": 100000000 } }
        ],
        "transitions": [
          {
            "state_name": "warm",
            "conditions": { "min_index_age": "30d" }
          }
        ]
      },
      {
        "name": "warm",
        "actions": [
          { "read_only": {} }
        ],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "180d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [ { "delete": {} } ],
        "transitions": []
      }
    ]
  }
}
```

#### Política de retención para alertas (365 días)

```json
PUT _plugins/_ism/policies/alerts-retention-365d
{
  "policy": {
    "description": "Retention policy for Suricata/Brain alerts — 365 days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "warm",
            "conditions": { "min_index_age": "90d" }
          }
        ]
      },
      {
        "name": "warm",
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
        "actions": [ { "delete": {} } ],
        "transitions": []
      }
    ]
  }
}
```

#### Política de retención para PCAP (30 días)

```json
PUT _plugins/_ism/policies/pcap-retention-30d
{
  "policy": {
    "description": "Retention policy for PCAP captures — 30 days max",
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
        "actions": [ { "delete": {} } ],
        "transitions": []
      }
    ]
  }
}
```

#### Asignación de políticas a index templates

```json
PUT _index_template/zeek-conn
{
  "index_patterns": ["zeek-conn-*"],
  "template": {
    "settings": {
      "index.plugins.index_state_management.rollover_alias": "zeek-conn",
      "index.plugins.index_state_management.policy_id": "zeek-retention-180d",
      "index.default_pipeline": "pseudonymize_ips"
    }
  }
}

PUT _index_template/suricata-alerts
{
  "index_patterns": ["suricata-alerts-*"],
  "template": {
    "settings": {
      "index.plugins.index_state_management.rollover_alias": "suricata-alerts",
      "index.plugins.index_state_management.policy_id": "alerts-retention-365d",
      "index.default_pipeline": "pseudonymize_ips"
    }
  }
}
```

### 3.4 Implementación en Wazuh

Wazuh gestiona la retención de logs a través de su integración con OpenSearch/elasticsearch.
La política de retención se aplica en el backend de almacenamiento (OpenSearch), no en el
manager de Wazuh directamente.

**Configuración adicional en Wazuh:**
- `ossec.conf → global → jsonout_output`: habilitar salida JSON para integración con OpenSearch
- `ossec.conf → logs → log_format`: configurar rotación local de logs del manager
- File rotation local: 31 días máximo en disco del manager, el resto en OpenSearch

### 3.5 Retención extendida para incidentes (excepción)

Cuando se abre un incidente confirmado, las evidencias asociadas se mueven a un índice
separado con política de retención extendida (3-5 años) y almacenamiento WORM:

```json
PUT _plugins/_ism/policies/evidence-retention-5y
{
  "policy": {
    "description": "Retention policy for forensic evidence — 5 years",
    "default_state": "locked",
    "states": [
      {
        "name": "locked",
        "actions": [
          { "read_only": {} }
        ],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "1825d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [ { "delete": {} } ],
        "transitions": []
      }
    ]
  }
}
```

> **Procedimiento:** Solo el SOC Lead o IR Team puede mover evidencias a este índice, y
> debe registrarse en la cadena de custodia (ver sección 7).

---

## 4. Seudonimización y anonimización de IPs

### 4.1 Distinción conceptual

| Aspecto | Seudonimización | Anonimización |
|--------|----------------|---------------|
| **Definición GDPR** | Art. 4(5): tratamiento de modo que ya no puedan atribuirse a un interesado sin información adicional | Cons. 26: datos que no pueden referirse a una persona identificada o identificable |
| **¿Dato personal?** | ✅ Sigue siendo dato personal | ❌ No es dato personal |
| **Reversibilidad** | Reversible con clave | Irreversible |
| **Aplicabilidad GDPR** | Completa | No aplica |
| **Uso en KhaiNet** | Operaciones SOC diarias | Reportes agregados, estadísticas |

### 4.2 Estrategia de seudonimización por defecto

**Principio rector:** En operaciones rutinarias del SOC, las IPs se almacenan
**seudonimizadas**. El acceso a IPs en claro requiere autorización y se audita.

#### Técnicas disponibles

| Técnica | Descripción | Ventajas | Desventajas | Uso en KhaiNet |
|---------|------------|---------|------------|---------------|
| **Hash con sal (SHA-256)** | `SHA256(IP + salt_secreto)` | Determinista, permite correlación sin revelar IP | Ataque de diccionario (espacio de IPs finito); la sal debe ser robusta | ✅ Operaciones SOC diarias |
| **Truncamiento** | `192.168.1.42 → 192.168.1.0/24` | Simple, reduce granularidad | Pierde capacidad de distinguir hosts en misma subred | Reportes agregados |
| **Tokenización** | IP → token aleatorio con mapeo en vault | Reversible bajo control, no determinista | Requiere infraestructura de vault | Alternativa avanzada |
| **Generalización** | `192.168.1.42 → 192.168.0.0/16` | Máxima privacidad en reportes | Insuficiente para operaciones SOC | Dashboards de dirección |

#### Recomendación de implementación

- **Técnica principal:** Hash SHA-256 con sal de mínimo 32 bytes
- **Sal:** Almacenada en secreto, separada de los logs, rotada anualmente
- **Subred preservada:** Se mantiene el prefijo /24 para análisis de routing y detección
  de movimientos laterales dentro de subredes
- **Vault de mapeo reversible:** Índice OpenSearch separado, acceso restringido, auditado

### 4.3 Cuándo seudonimizar vs anonimizar vs IP en claro

| Escenario | Técnica | Acceso requerido |
|----------|---------|-----------------|
| Operaciones SOC diarias (detección, triage) | Seudonimización (hash+sal) | SOC Analyst Tier 1/2 |
| Dashboards de métricas y tendencias | Truncamiento /24 | Cualquier rol con acceso a dashboards |
| Reportes a dirección / externos | Anonimización (agregación) | Autorización específica |
| Investigación de incidente activo | IP en claro | SOC Lead / IR (con incidente abierto) |
| Compartir IOCs con terceros | IP en claro para externas; seudonimizadas para internas | Detection Engineer |
| Entrenamiento de modelos IA (Brain) | Seudonimización (preserva patrones) | Data Science / Detection Eng. |

### 4.4 Implementación en OpenSearch

#### 4.4.1 Ingest pipeline de seudonimización

```json
PUT _ingest/pipeline/pseudonymize_ips
{
  "description": "Pseudonymize source and destination IPs using salted SHA-256 hash. Preserves /24 subnet (IPv4) or /64 prefix (IPv6) for routing analysis.",
  "processors": [
    {
      "script": {
        "source": """
          // Salt inyectada vía params desde el OpenSearch Keystore — NO hardcodear
          // Configurar con: ./bin/opensearch-keystore add khainet.ip.salt
          // Y en opensearch.yml: khainet.ip.salt: ${khainet.ip.salt}
          def salt = params['ip_salt'];

          // Codificación hex manual (compatible con Painless — no usar encodeHex de Groovy)
          def toHex = { bytes ->
            def sb = new StringBuilder();
            for (def b : bytes) {
              sb.append(String.format('%02x', b & 0xff));
            }
            return sb.toString();
          };

          // Hash SHA-256 de IP + sal, truncado a 16 chars hex (64 bits)
          // Truncación justificada: espacio de IPs internas es pequeño (<2^32);
          // 64 bits de hash son suficientes para evitar colisiones en este dominio.
          def hashIp = { ip ->
            def md = java.security.MessageDigest.getInstance('SHA-256');
            md.update((ip + salt).getBytes('UTF-8'));
            return toHex(md.digest()).substring(0, 16);
          };

          // Seudonimizar IP de origen
          if (ctx.source_ip != null) {
            ctx.source_ip_pseudo = hashIp(ctx.source_ip);
            // Preservar subred para análisis de routing
            if (ctx.source_ip.contains('.')) {
              // IPv4: preservar /24
              def parts = ctx.source_ip.splitOnToken('.');
              if (parts.length == 4) {
                ctx.source_ip_subnet = parts[0] + '.' + parts[1] + '.' + parts[2] + '.0/24';
              }
            } else if (ctx.source_ip.contains(':')) {
              // IPv6: preservar /64
              def parts = ctx.source_ip.splitOnToken(':');
              if (parts.length >= 4) {
                ctx.source_ip_subnet = parts[0] + ':' + parts[1] + ':' + parts[2] + ':' + parts[3] + '::/64';
              }
            }
          }

          // Seudonimizar IP de destino
          if (ctx.dest_ip != null) {
            ctx.dest_ip_pseudo = hashIp(ctx.dest_ip);
            if (ctx.dest_ip.contains('.')) {
              def parts = ctx.dest_ip.splitOnToken('.');
              if (parts.length == 4) {
                ctx.dest_ip_subnet = parts[0] + '.' + parts[1] + '.' + parts[2] + '.0/24';
              }
            } else if (ctx.dest_ip.contains(':')) {
              def parts = ctx.dest_ip.splitOnToken(':');
              if (parts.length >= 4) {
                ctx.dest_ip_subnet = parts[0] + ':' + parts[1] + ':' + parts[2] + ':' + parts[3] + '::/64';
              }
            }
          }
        """,
        "lang": "painless",
        "params": {
          "ip_salt": "INJECT_FROM_KEYSTORE"
        }
      }
    },
    {
      "remove": { "field": "source_ip", "ignore_missing": true }
    },
    {
      "remove": { "field": "dest_ip", "ignore_missing": true }
    }
  ]
}
```

> **Nota de seguridad crítica:** El valor `"INJECT_FROM_KEYSTORE"` es un placeholder.
> En producción, la sal se inyecta desde el OpenSearch Keystore y nunca aparece en el
> cuerpo del pipeline. Rotar anualmente. La sal debe tener mínimo 32 bytes de entropía.

#### 4.4.2 Índice vault para mapeo reversible

```json
// Índice separado, acceso restringido, encriptado
PUT ip-vault
{
  "settings": {
    "index": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    }
  },
  "mappings": {
    "properties": {
      "ip_hash":     { "type": "keyword" },
      "ip_original": { "type": "ip" },
      "created_at":  { "type": "date" },
      "last_seen":   { "type": "date" }
    }
  }
}
```

#### 4.4.3 Transform para agregaciones anónimas

```json
PUT _transform/zeek-conn-anonymized-daily
{
  "source": { "index": "zeek-conn-*" },
  "dest": { "index": "zeek-conn-anonymized-daily" },
  "pivot": {
    "group_by": {
      "source_ip_subnet": { "terms": { "field": "source_ip_subnet" } },
      "dest_port":        { "terms": { "field": "dest_port" } }
    },
    "aggregations": {
      "connection_count": { "value_count": { "field": "source_ip_pseudo" } },
      "bytes_total":      { "sum": { "field": "orig_bytes" } }
    }
  },
  "schedule": { "interval": "1d" }
}
```

### 4.5 Modelo de acceso a IPs (reversibilidad controlada)

| Rol | IPs seudonimizadas | IPs en claro | Vault de mapeo |
|-----|-------------------|-------------|---------------|
| **SOC Analyst Tier 1** | ✅ Sí | ❌ No | ❌ No |
| **SOC Analyst Tier 2** | ✅ Sí | ✅ Sí (con incidente abierto) | ❌ No |
| **SOC Lead / IR** | ✅ Sí | ✅ Sí | ✅ Sí (con aprobación dual) |
| **DPO** | ✅ Sí | ❌ No (por defecto) | ✅ Sí (auditoría) |
| **Detection Engineer** | ✅ Sí | ❌ No | ❌ No |
| **Platform/Infra Admin** | ❌ No (acceso a infra, no a datos) | ❌ No | ❌ No |
| **Dirección** | ✅ Solo agregados | ❌ No | ❌ No |

### 4.6 Procedimiento de re-identificación

1. **Solicitud formal** con justificación (incidente activo, investigación autorizada)
2. **Aprobación dual:** SOC Lead + DPO (control de dos personas)
3. **Registro de auditoría:** quién, cuándo, qué IP, motivo
4. **Acceso temporal** con expiración automática (ej. 4 horas)
5. **Revisión trimestral** de todos los accesos al vault por el DPO

---

## 5. Gobernanza de detección y respuesta

### 5.1 Ciclo de vida de reglas de detección

```
[Propuesta] → [Revisión técnica] → [Revisión privacidad DPO] → [Aprobación] → [Despliegue] → [Monitorización] → [Revisión periódica]
```

#### Roles en el ciclo de vida

| Rol | Responsabilidad |
|-----|----------------|
| **Detection Engineer** | Diseña y propone reglas Suricata, scripts Zeek, reglas Wazuh, modelos de anomalías |
| **SOC Lead** | Revisión técnica: calidad, cobertura, falsos positivos esperados |
| **DPO** | Revisión de privacidad: ¿la regla captura datos innecesarios? ¿impacto en privacidad? |
| **CISO / Security Manager** | Aprobación final de reglas de alta criticidad |
| **SOC Analysts** | Feedback sobre falsos positivos/negativos en operación |

#### Revisión periódica

| Frecuencia | Actividad |
|-----------|----------|
| **Mensual** | Tuning de reglas con alto número de falsos positivos |
| **Trimestral** | Cobertura de reglas vs. nuevas amenazas; revisión MITRE ATT&CK mapping |
| **Anual** | Revisión completa del catálogo de reglas; retirada de reglas obsoletas; validación de necesidad |

#### Implementación recomendada

- Repositorio **Git** para reglas de Suricata, scripts de Zeek y reglas de Wazuh
- **Pull requests** con revisiones obligatorias: code review (SOC Lead) + DPO review
- **CI/CD** para despliegue controlado (staging → production)
- Cada regla documentada con: propósito, datos que captura, severidad, técnica MITRE
  ATT&CK, fecha de creación, fecha de última revisión

### 5.2 Separación de funciones (SoD)

| Función | Rol responsable | Separado de |
|--------|----------------|-------------|
| Monitorización y detección | SOC Analyst (Tier 1/2) | Respuesta a incidentes, administración de sistemas |
| Respuesta a incidentes | IR Team / SOC Lead | Monitorización rutinaria |
| Administración de plataformas | Platform/Infra Admin | Operaciones SOC, respuesta a incidentes |
| Gestión de reglas de detección | Detection Engineer | Operaciones SOC (no opera con sus propias reglas) |
| Auditoría y compliance | DPO / Compliance | Todas las funciones operativas |
| Aprobación de acciones críticas | SOC Lead / CISO | Ejecución de acciones críticas |

**Principio:** Ninguna persona debe tener capacidad de ejecutar una acción crítica sin
control independiente. Un analyst no debe poder modificar reglas de detección que él mismo
monitorea.

**Implementación técnica:**
- RBAC en OpenSearch Security Plugin con roles separados
- Cuentas de servicio separadas para Shuffle (SOAR) vs. analysts humanos
- MFA obligatorio para todos los accesos
- Audit logging de todas las acciones administrativas

### 5.3 Gobernanza de respuestas automatizadas (Shuffle SOAR)

#### Niveles de autonomía

| Nivel | Descripción | Ejemplo | Aprobación requerida |
|-------|------------|---------|---------------------|
| **0 — Notificación** | Solo informa | Enviar alerta a Slack/email | DPO + SOC Lead (despliegue inicial) |
| **1 — Enriquecimiento** | Consulta datos, no actúa | Threat intel lookup, geolocalizar IP | DPO + SOC Lead |
| **2 — Contención baja** | Acciones reversibles, bajo impacto | Bloquear IP en firewall por 1h (timeout auto) | CISO + DPO |
| **3 — Contención alta** | Acciones reversibles, alto impacto | Aislar endpoint, bloquear cuenta de usuario | CISO + DPO + política pre-aprobada |
| **4 — Irreversible** | Acciones no reversibles o críticas | Eliminar datos, bloquear sistema crítico | **Aprobación humana obligatoria** (no automático) |

#### Ciclo de gobernanza de playbooks

1. **Diseño:** Detection Engineer + IR diseñan el playbook
2. **Revisión de privacidad:** DPO evalúa tratamiento de datos personales, minimización,
   proporcionalidad de acciones automatizadas
3. **Revisión de seguridad:** SOC Lead evalúa riesgo (¿puede un atacante inducir el
   playbook para causar daño?)
4. **Aprobación:** CISO aprueba playbooks Nivel 2+; DPO aprueba todos
5. **Testing:** Ejecución en entorno de pruebas antes de producción
6. **Monitorización:** Audit log de cada ejecución; revisión semanal de ejecuciones
   automatizadas
7. **Revisión periódica:** Trimestral (eficacia) y anual (reaprobación)

#### Consideraciones específicas para Shuffle

- **Variables en workflows:** No incluir datos personales en variables de texto plano que
  se envíen a APIs externas (Slack, email, webhooks)
- **Webhooks externos:** Asegurar cumplimiento GDPR de endpoints (transferencias a
  terceros países — Art. 44-49)
- **Logging de ejecución:** Shuffle debe registrar qué playbook se ejecutó, con qué datos
  de entrada, y qué acciones tomó
- **Timeout y rate limiting:** Configurar límites para evitar bucles infinitos o acciones
  masivas no deseadas

#### Art. 22 GDPR — Decisiones automatizadas

El Art. 22 GDPR otorga al interesado el derecho a no ser objeto de decisiones basadas
únicamente en el tratamiento automatizado que produzcan efectos jurídicos o le afecten
significativamente. Aunque las alertas de seguridad de KhaiNet **no constituyen por sí
mismas decisiones con efectos jurídicos sobre personas**, los playbooks SOAR de Nivel 3-4
(bloqueo de cuentas de usuario, aislamiento de endpoints) sí pueden afectar
significativamente a un empleado.

**Salvaguardias para cumplir el Art. 22:**
- Los playbooks de Nivel 3 (contención alta) requieren **política pre-aprobada** por CISO
  + DPO, con revisión humana posterior de cada ejecución
- Los playbooks de Nivel 4 (irreversible) requieren **aprobación humana obligatoria**
  antes de la ejecución — nunca son completamente automatizados
- Todo individuo afectado por una acción automatizada de contención debe ser **informado**
  y puede solicitar revisión humana (Art. 22(3))
- Se mantiene un **registro auditable** de cada decisión automatizada para permitir
  revisión humana posterior

### 5.4 Gobernanza de modelos de IA (Brain y anomalías)

Los modelos de IA de KhaiNet (Isolation Forest, Autoencoders, HMM, Brain) requieren
gobernanza específica:

| Aspecto | Política |
|--------|---------|
| **Entrenamiento** | Los modelos se entrenan sobre logs seudonimizados. No se exponen IPs en claro al pipeline de entrenamiento. |
| **Versionado** | Todos los modelos se versionan en Git (pesos, hiperparámetros, métricas de validación) |
| **Validación** | Cada versión de modelo debe pasar validación: precisión, falsos positivos, latencia. Aprobación por SOC Lead. |
| **Drift detection** | Monitorización mensual de drift en distribución de features. Re-entrenamiento si drift > umbral. |
| **Explicabilidad (XAI)** | Brain debe generar explicación legible del razonamiento detrás de cada correlación. |
| **Auditoría de sesgos** | Revisión anual de sesgos en detección (¿algún grupo de usuarios/hosts es sistemáticamente más alertado?) |
| **Datos de entrenamiento** | Los datasets de entrenamiento no contienen datos personales en claro. Seudonimización aplicada. |

---

## 6. Roles y responsabilidades

### 6.1 Matriz RACI

| Actividad | SOC Analyst | SOC Lead | IR Team | Detection Eng. | Infra Admin | DPO | CISO |
|----------|:-----------:|:--------:|:-------:|:--------------:|:-----------:|:---:|:----:|
| Monitorización 24/7 | **R** | A | I | I | I | I | I |
| Triage de alertas | **R** | A | C | I | — | I | I |
| Investigación de incidentes | C | A | **R** | C | C | I | I |
| Diseño de reglas de detección | I | A | C | **R** | — | C | I |
| Aprobación de reglas | I | **R** | I | C | — | C | A |
| Revisión de privacidad de reglas | I | I | I | C | — | **R** | I |
| Despliegue de infraestructura | — | I | — | C | **R** | I | A |
| Acceso a IPs en claro | I | **R** | **R** | I | — | C | A |
| Aprobación de playbooks SOAR | I | C | C | C | — | C | **R** |
| Notificación de brecha (72h) | I | C | C | — | I | **R** | A |
| Auditoría de accesos | I | I | I | I | I | **R** | A |
| Revisión de LIA/DPIA | I | C | I | I | I | **R** | A |

> **R** = Responsable · **A** = Aprobador · **C** = Consultado · **I** = Informado

### 6.2 Descripción de roles

#### SOC Analyst (Tier 1 / Tier 2)

**Tier 1 — Monitorización inicial:**
- Monitorización continua de dashboards y alertas en OpenSearch
- Triage inicial de alertas: clasificar como verdadero/falso positivo
- Escalado a Tier 2 o IR según severidad
- Acceso a IPs seudonimizadas únicamente
- No puede modificar reglas de detección ni ejecutar playbooks de contención

**Tier 2 — Análisis avanzado:**
- Investigación profunda de alertas escaladas
- Acceso a IPs en claro con incidente abierto autorizado
- Correlación manual de eventos en OpenSearch
- Puede ejecutar playbooks de Nivel 0-1 (notificación, enriquecimiento)
- Escalado a IR Team para incidentes confirmados

#### SOC Lead

- Supervisión del equipo de analistas
- Revisión técnica de reglas de detección propuestas
- Aprobación de solicitudes de re-identificación de IPs (junto con DPO)
- Revisión semanal de ejecuciones automatizadas de Shuffle
- Punto de escalado para incidentes de alta severidad
- Responsable de la calidad de la detección (métricas de cobertura/precisión)

#### IR Team (Respuesta a Incidentes)

- Investigación y contención de incidentes confirmados
- Acceso a IPs en claro y vault de mapeo durante incidentes activos
- Ejecución de playbooks de Nivel 2-3 (con aprobación pre-aprobada)
- Recolección y preservación de evidencias (cadena de custodia)
- Coordinación con DPO para notificación de brechas
- Post-mortem y lecciones aprendidas

#### Detection Engineer

- Diseño, desarrollo y mantenimiento de reglas de Suricata, scripts de Zeek, reglas de Wazuh
- Desarrollo y entrenamiento de modelos de anomalías (Isolation Forest, Autoencoders, HMM)
- Tuning de umbrales basado en feedback del SOC y etiquetas de Darktrace
- No realiza operaciones de monitorización rutinaria (separación de funciones)
- Mantenimiento del repositorio Git de reglas con PRs y revisiones

#### Platform / Infra Admin

- Despliegue y mantenimiento de la infraestructura KhaiNet (Zeek, Suricata, Wazuh,
  OpenSearch, Shuffle)
- Gestión de clusters, storage, redes, backups
- Aplicación de parches y actualizaciones
- **No tiene acceso a datos de logs ni a IPs** (acceso a infraestructura, no a datos)
- Configuración de ISM, ingest pipelines, RBAC (bajo instrucción del SOC Lead y DPO)

#### DPO (Delegado de Protección de Datos)

- **Designación obligatoria** (Art. 37(1)(b): observación habitual y sistemática a gran
  escala — KhaiNet cumple este criterio)
- Revisión y aprobación de la LIA (Evaluación de Interés Legítimo)
- Realización y revisión anual de la DPIA (Art. 35)
- Revisión de privacidad de reglas de detección y playbooks SOAR
- Auditoría trimestral de accesos a IPs en claro y al vault de mapeo
- Coordinación de notificación de brechas a la autoridad (Art. 33: 72h) y a interesados
  (Art. 34)
- Formación anual del personal SOC en privacidad y GDPR
- Punto de contacto con la autoridad de protección de datos
- **Independencia garantizada** (Art. 38): no recibe instrucciones, reporta al máximo
  nivel directivo, no tiene conflicto de intereses (no puede ser CISO ni SOC Lead)

#### CISO / Security Manager

- Responsable último de la seguridad de la información
- Aprobación final de reglas de detección de alta criticidad
- Aprobación de playbooks SOAR de Nivel 2+
- Aprobación de la estrategia de shadow mode y go/no-go
- Reporta a dirección sobre métricas y postura de seguridad

---

## 7. Cadena de custodia digital

### 7.1 Marco normativo

| Norma | Ámbito |
|-------|--------|
| **ISO/IEC 27037:2012** | Identificación, recolección, adquisición y preservación de evidencias digitales |
| **ISO/IEC 27041:2015** | Aseguramiento de la idoneidad del método de investigación |
| **ISO/IEC 27042:2015** | Análisis e interpretación de evidencias digitales |
| **ISO/IEC 27043:2015** | Principios y procesos para la investigación de incidentes |
| **ISO/IEC 27050-1:2019** | Discovery electrónico (e-discovery) |

### 7.2 Fases del procedimiento (ISO 27037)

#### Fase 1: Identificación

Identificar qué evidencias existen y dónde:

| Tipo de evidencia | Origen en KhaiNet |
|------------------|-------------------|
| Logs de conexión | Zeek (conn.log) en OpenSearch |
| Logs DNS | Zeek (dns.log) en OpenSearch |
| Logs HTTP | Zeek (http.log) en OpenSearch |
| Logs SSL | Zeek (ssl.log) en OpenSearch |
| Alertas IDS | Suricata (eve.json) en OpenSearch |
| Logs de host | Wazuh en OpenSearch |
| Capturas de paquetes | PCAP (si disponible, rotación 7-30 días) |
| Capturas de memoria | Volcado con LiME/WinPMem (si se requiere) |
| Correlaciones de Brain | Output de Brain en OpenSearch |
| Logs de auditoría | OpenSearch Audit Log |

**Documentar:** tipo de evidencia, ubicación, sistema origen, timestamp exacto.

#### Fase 2: Recolección

- **Principio de no alteración:** La recolección no debe modificar los datos originales
- Para logs en OpenSearch: exportar a formato inmutable (JSON a archivo con hash inmediato)
- Para PCAP: copiar sin modificar el original
- **Documentar:** quién recolecta, método, herramientas usadas, fecha/hora exacta (UTC)

#### Fase 3: Adquisición

- Crear copia de trabajo para análisis, preservando el original
- Calcular **hash criptográfico SHA-256** de la evidencia original inmediatamente
- Almacenar el original en medio **WORM** (Write Once Read Many) o equivalente
- **Documentar:** hash calculado, medio de almacenamiento, cadena de custodia iniciada

#### Fase 4: Preservación

- Mantener la evidencia en condiciones que aseguren su integridad
- Control de acceso físico y lógico
- Registro de toda manipulación (quién, cuándo, qué acción)
- **Documentar:** condiciones de almacenamiento, accesos, transferencias

### 7.3 Hash e integridad

- **Algoritmo:** SHA-256 mínimo (SHA-1 y MD5 no son aceptables para evidencia)
- **Momento del cálculo:** Inmediatamente después de la recolección, antes de cualquier
  procesamiento
- **Verificación:** Recalcular hash en cada transferencia de custodia y antes de análisis
- **Almacenamiento del hash:** En registro separado, no en el mismo medio que la evidencia

### 7.4 Timestamps y sincronización

- **NTP sincronizado** en todos los sistemas KhaiNet (Zeek, Suricata, Wazuh, OpenSearch)
- Timestamps en **UTC** con precisión de milisegundos
- Documentar la fuente de tiempo y la precisión de sincronización
- Para evidencias críticas: considerar timestamps con firma digital (RFC 3161 — Time Stamp
  Protocol)

### 7.5 Almacenamiento WORM

| Opción | Descripción | Ventajas | Desventajas |
|--------|------------|---------|------------|
| **NAS con snapshots inmutables** | Snapshots NetApp/QNAP con retención inmutable | On-premise, control total | Coste de infraestructura |
| **S3 con Object Lock (Compliance Mode)** | Almacenamiento inmutable en cloud | Escalable, integración nativa | Dependencia cloud, transferencias internacionales |
| **OpenSearch Snapshot Repository read-only** | Snapshot a repositorio NFS/S3 read-only | Integración nativa con OpenSearch | No es WORM estricto (admin puede cambiar permisos) |
| **Linux chattr +i** | Atributo de archivo inmutable a nivel de SO | Simple, gratuito | Requiere root, no es WORM estricto |

**Recomendación para KhaiNet:** Para evidencias de incidentes confirmados, usar **NAS con
snapshots inmutables** (preferido on-premise) o S3 con Object Lock Compliance Mode. Para
logs rutinarios, ISM de OpenSearch con eliminación automática es suficiente.

### 7.6 Plantilla de registro de cadena de custodia

```
========================================================================
REGISTRO DE CADENA DE CUSTODIA — INCIDENTE [INC-2026-XXX]
========================================================================

1. IDENTIFICACIÓN DEL INCIDENTE
   ID del incidente:      INC-2026-XXX
   Descripción:           [breve descripción]
   Fecha de detección:    [YYYY-MM-DD HH:MM:SS UTC]
   Detectado por:         [nombre, rol]
   Severidad:             [Crítica / Alta / Media / Baja]

2. EVIDENCIA
   ID de evidencia:       EV-001
   Tipo:                  [PCAP / Log Zeek / Alerta Suricata / Log Wazuh / Memoria / Correlación Brain]
   Descripción:           [ej. "conn.log del sensor zeek-prod-01 para ventana 2026-07-01 10:00-12:00 UTC"]
   Sistema origen:        [hostname/IP del sensor o componente]
   Ubicación original:    [índice OpenSearch / ruta de archivo]
   Tamaño:                [bytes]
   Hash SHA-256:          [hash]

3. RECOLECCIÓN
   Recopilado por:        [nombre, rol]
   Fecha/hora (UTC):      [YYYY-MM-DD HH:MM:SS]
   Método:                [ej. "Export desde OpenSearch API a archivo JSON"]
   Herramientas:          [ej. "curl + jq + sha256sum"]
   Hash verificado:       [✅ / ❌]

4. ALMACENAMIENTO
   Ubicación:             [ruta del medio WORM]
   Medio:                 [NAS inmutable / S3 Object Lock / DVD-R]
   Fecha de almacenamiento: [YYYY-MM-DD HH:MM:SS UTC]
   Almacenado por:        [nombre, rol]

5. TRANSFERENCIAS DE CUSTODIA
   | # | De          | A           | Fecha/hora (UTC)       | Motivo          | Hash verificado |
   |---|-------------|-------------|------------------------|-----------------|-----------------|
   | 1 | [nombre]    | [nombre]    | [YYYY-MM-DD HH:MM:SS]  | [motivo]        | ✅ / ❌          |
   | 2 | ...         | ...         | ...                    | ...             | ...             |

6. ACCESOS
   | # | Quién       | Fecha/hora (UTC)       | Propósito           | Acciones realizadas    |
   |---|-------------|------------------------|---------------------|------------------------|
   | 1 | [nombre]    | [YYYY-MM-DD HH:MM:SS]  | [análisis/consulta] | [descripción]          |

7. DISPOSICIÓN FINAL
   Fecha de disposición:  [YYYY-MM-DD]
   Método:                [destrucción / retorno / archivo permanente]
   Autorizado por:        [nombre, rol]
   Hash final verificado: [✅ / ❌]

========================================================================
```

### 7.7 Audit logging de la cadena de custodia

- Todo acceso a evidencias debe registrarse en un **audit log inmutable**
- El audit log debe incluir: quién, qué evidencia, cuándo, qué acción (lectura /
  transferencia / eliminación), desde qué IP
- El audit log en sí debe estar protegido contra modificación (WORM o append-only)
- En OpenSearch: usar el Security Plugin Audit Logging con índice de audit separado y
  protegido con política de retención de 5 años

---

## 8. Notificación de brechas (Art. 33-34 GDPR)

### 8.1 Procedimiento

KhaiNet, como sistema de detección, puede descubrir brechas de seguridad que afecten a
datos personales. El procedimiento de notificación es:

```
[Detección de brecha por KhaiNet]
    → [IR Team confirma brecha de datos personales]
    → [Notificación al DPO en <1h]
    → [DPO evalúa riesgo para derechos y libertades]
    → [¿Riesgo alto?]
        → Sí: Notificación a autoridad (AGPD/AEPD) en <72h (Art. 33)
              + Notificación a interesados (Art. 34)
        → No: Documentación interna del incidente (Art. 33(5))
```

### 8.2 Plazos

| Acción | Plazo | Responsable |
|--------|-------|------------|
| Notificación al DPO tras confirmar brecha | < 1 hora | IR Team |
| Evaluación de riesgo por DPO | < 24 horas | DPO |
| Notificación a autoridad de protección de datos | < 72 horas desde detección | DPO |
| Notificación a interesados | Sin demora indebida | DPO + CISO |
| Documentación interna de la brecha | Permanente (Art. 33(5)) | DPO |

### 8.3 Contenido de la notificación a la autoridad (Art. 33(3))

1. Descripción de la naturaleza de la brecha (categorías de datos afectados, nº aprox. de
   interesados y registros)
2. Nombre y datos de contacto del DPO
3. Descripción de las consecuencias probables
4. Descripción de las medidas adoptadas o propuestas (mitigación, protección de
   interesados)

---

## 9. DPIA — Evaluación de Impacto en Protección de Datos

### 9.1 Obligatoriedad

Una DPIA (Art. 35) es **obligatoria** para KhaiNet porque:
- La monitorización de red es tratamiento a gran escala (Art. 35(3)(b))
- Es observación habitual y sistemática de personas
- Puede implicar datos especiales del Art. 9 si se capturan payloads HTTP

### 9.2 Contenido mínimo

1. **Descripción sistemática del tratamiento:** componentes KhaiNet, flujos de datos,
   tipos de datos personales tratados (ver sección 2.2)
2. **Evaluación de necesidad y proporcionalidad:** LIA (ver sección 2.4)
3. **Evaluación de riesgos** para derechos y libertades de los interesados:
   - Re-identificación indebida de IPs
   - Acceso no autorizado a logs con datos personales
   - Uso de datos de red para fines no de seguridad (vigilancia laboral)
   - Captura excesiva de datos (payloads HTTP con datos sensibles)
   - Retención excesiva
4. **Medidas para mitigar riesgos:** seudonimización, RBAC, retención automática, audit
   logging, cadena de custodia, formación, prohibición de uso no de seguridad

### 9.3 Revisión

- Revisión **anual** de la DPIA
- Revisión **ad hoc** cuando cambien los casos de uso, se añadan nuevos componentes, o se
  modifiquen las políticas de retención/seudonimización

---

## 10. Checklist de implementación

### Cumplimiento legal

- [ ] **LIA** documentada y aprobada por DPO
- [ ] **DPIA** realizada para la plataforma NDR completa
- [ ] **Registro de actividades de tratamiento** (Art. 30) actualizado
- [ ] **Designación de DPO** formalizada (Art. 37)
- [ ] **Información a empleados/usuarios** sobre la monitorización (Art. 13/14)
- [ ] **Procedimiento de notificación de brechas** (Art. 33-34) documentado y probado

### Medidas técnicas

- [ ] **Política de retención** definida con ISM en OpenSearch (180 días logs, 365 alertas, 30 PCAP)
- [ ] **Seudonimización** de IPs implementada en ingest pipelines de OpenSearch
- [ ] **Vault de mapeo** reversible con acceso restringido y auditado
- [ ] **RBAC** configurado en OpenSearch Security Plugin con roles separados (SoD)
- [ ] **Audit logging** habilitado y almacenado de forma inmutable (5 años)
- [ ] **NTP sincronizado** en todos los componentes (Zeek, Suricata, Wazuh, OpenSearch)
- [ ] **Cifrado** en tránsito (TLS) y en reposo para OpenSearch
- [ ] **MFA** obligatorio para todos los accesos

### Gobernanza

- [ ] **Repositorio Git** para reglas de detección con PRs y revisiones obligatorias
- [ ] **Catálogo de playbooks** Shuffle clasificados por nivel de autonomía (0-4)
- [ ] **Aprobación formal** de cada playbook por CISO + DPO
- [ ] **Procedimiento de re-identificación** de IPs con control dual (SOC Lead + DPO)
- [ ] **Procedimiento de cadena de custodia** documentado y probado
- [ ] **Revisión periódica** de reglas (trimestral) y playbooks (trimestral)

### Formación y cultura

- [ ] **Formación anual** del personal SOC en privacidad y GDPR
- [ ] **Formación específica** en cadena de custodia para IR Team
- [ ] **Política de uso aceptable** de datos de red (prohibición de vigilancia laboral)

---

## 11. Referencias normativas

### GDPR (Reglamento UE 2016/679)

| Artículo | Contenido | URL |
|----------|----------|-----|
| Art. 4(1) | Definición de dato personal | https://gdpr-info.eu/art-4-gdpr/ |
| Art. 4(5) | Definición de seudonimización | https://gdpr-info.eu/art-4-gdpr/ |
| Art. 5 | Principios relativos al tratamiento | https://gdpr-info.eu/art-5-gdpr/ |
| Art. 6(1)(f) | Licitud — interés legítimo | https://gdpr-info.eu/art-6-gdpr/ |
| Art. 13-14 | Información al interesado | https://gdpr-info.eu/art-13-gdpr/ |
| Art. 22 | Decisiones automatizadas individuales | https://gdpr-info.eu/art-22-gdpr/ |
| Art. 25 | Protección de datos por diseño y por defecto | https://gdpr-info.eu/art-25-gdpr/ |
| Art. 30 | Registro de actividades de tratamiento | https://gdpr-info.eu/art-30-gdpr/ |
| Art. 32 | Seguridad del tratamiento | https://gdpr-info.eu/art-32-gdpr/ |
| Art. 33-34 | Notificación de brechas | https://gdpr-info.eu/art-33-gdpr/ |
| Art. 35 | Evaluación de impacto (DPIA) | https://gdpr-info.eu/art-35-gdpr/ |
| Art. 37-39 | Delegado de protección de datos (DPO) | https://gdpr-info.eu/art-37-gdpr/ |
| Art. 44-49 | Transferencias internacionales | https://gdpr-info.eu/art-44-gdpr/ |
| Cons. 26 | Datos anónimos vs seudonimizados | https://gdpr-info.eu/recitals/no-26/ |
| Cons. 30 | Identificadores en línea (IPs) | https://gdpr-info.eu/recitals/no-30/ |
| Cons. 49 | Seguridad como interés legítimo | https://gdpr-info.eu/recitals/no-49/ |

### Jurisprudencia

- **CJUE C-582/14 (Breyer vs. Alemania, 19 octubre 2016):** Las IPs dinámicas son datos
  personales cuando el responsable tiene medios legales para identificar al usuario.
  Disponible en: https://curia.europa.eu/ (buscar asunto C-582/14)

### Directrices y guías

- **EDPB Guidelines 9/2022 on Legitimate Interest (Art. 6(1)(f))** — Versión final
  adoptada en marzo de 2024. Disponible en: https://www.edpb.europa.eu/
- **WP29 Opinion 2/2017 on data processing at work (WP249)** — Monitorización de
  empleados. Disponible en: https://www.edpb.europa.eu/
- **ENISA Handbook on Security of Personal Data Processing (2018)** —
  https://www.enisa.europa.eu/publications/handbook-on-security-of-personal-data-processing

### Normativas ISO

| Norma | Título |
|-------|--------|
| ISO/IEC 27001:2022 | SGSI — Controles A.8.10 (Information deletion) y A.8.3 (Information storage) para retención |
| ISO/IEC 27037:2012 | Identificación, recolección, adquisición y preservación de evidencias digitales |
| ISO/IEC 27041:2015 | Aseguramiento de la idoneidad del método de investigación |
| ISO/IEC 27042:2015 | Análisis e interpretación de evidencias digitales |
| ISO/IEC 27043:2015 | Principios y procesos para la investigación de incidentes |
| ISO/IEC 27050-1:2019 | Discovery electrónico (e-discovery) |

### Normativas nacionales (España)

- **ENS — Esquema Nacional de Seguridad (RD 311/2022):** Requiere medidas de registro y
  auditoría. No especifica tiempos exactos pero requiere política definida.
- **LOPDGDD — Ley Orgánica 3/2018 de Protección de Datos Personales y garantía de los
  derechos digitales:** Desarrollo del GDPR en España.

---

*Documento generado para el proyecto KhaiNet — KH7 (Grupo Khlloreda)*
*Vinculado al documento de arquitectura: [darktrace-alternativa-software-libre.md](darktrace-alternativa-software-libre.md)*
