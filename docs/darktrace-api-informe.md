# Informe Técnico: Verificación de Acceso a la API de Darktrace

**Proyecto**: KhaiNet — Plataforma NDR open-source  
**Issue**: Verificar acceso a API de Darktrace (blocker crítico)  
**Fecha**: 2026-07-03  
**Autor**: Khai MAX (con investigación de researcher_agent)

---

## Resumen Ejecutivo

La API de Darktrace **sí existe y permite exportar alertas de forma programática** con suficiente detalle para entrenar modelos de IA. Sin embargo, hay **discrepancias críticas** entre lo que el módulo `tuning/` actual asume y la realidad de la API. El cliente necesita una reescritura sustancial antes de poder conectarse a una instancia real de Darktrace.

**Hallazgo crítico**: La retención típica de Darktrace (30-90 días) hace **imposible** consultar alertas de hace 12 meses al final del periodo de shadow mode. La estrategia debe modificarse para exportar continuamente desde el día 1.

**Estado**: Pendiente de confirmación humana sobre licencia y credenciales.

---

## 1. Autenticación

### Realidad de la API
Darktrace usa **token público/privado con firma HMAC-SHA1** por cada petición. No hay flujo OAuth ni JWT.

**Generación de tokens:**
1. Login como administrador en la instancia de Darktrace
2. System Config → API Keys
3. "Generate New API Key" → se obtienen `public_token` y `private_token`

**Headers requeridos en cada petición:**

| Header | Descripción |
|--------|-------------|
| `DTAPI-Token` | Token público |
| `DTAPI-Date` | Timestamp UTC en formato ISO (`YYYY-MM-DDTHH:MM:SS`) |
| `DTAPI-Signature` | Firma HMAC-SHA1 hexadecimal |
| `Content-Type` | `application/json` |

**Algoritmo de firma:**
```
macStr = "{request_path}?{sorted_params}\n{public_token}\n{utc_date}"
signature = HMAC-SHA1(private_token, macStr).hexdigest()
```

> ⚠️ **Crítico**: Los parámetros de query deben ir **ordenados alfabéticamente** tanto en la firma como en la petición real, o la API devuelve 401.

### Lo que asume el código actual
```python
headers["Authorization"] = f"Bearer {self.api_token}"
```

### ❌ Discrepancia: FATAL
El código usa un único Bearer token. La API real requiere dos tokens (público + privado) con firma HMAC-SHA1 por petición. **El cliente actual nunca se autenticará correctamente.**

---

## 2. Endpoints de Exportación de Alertas

### Endpoints principales para KhaiNet

| Endpoint | Método | Descripción | Relevancia para shadow mode |
|----------|--------|-------------|---------------------------|
| `/modelbreaches` | GET | **Model breach alerts** | ⭐ Principal: etiquetas supervisadas |
| `/aianalyst/incidentevents` | GET | AI Analyst incident events | Enriquecimiento de etiquetas |
| `/aianalyst/groups` | GET | Incidentes agrupados | Contexto de correlación |
| `/antigena` | GET | Acciones de RESPOND/Antigena | Requiere módulo RESPOND |
| `/advancedsearch` | GET/POST | Búsqueda avanzada de logs | Datos de red crudos |
| `/details` | GET | Detalles de eventos/conexiones | Detalle por breach |
| `/devices` | GET | Inventario de dispositivos | Mapeo de dispositivos |
| `/status` | GET | Estado del sistema, versión, licencia | Verificación inicial |
| `/models` | GET | Listado de modelos de detección | Catálogo de modelos |

### Parámetros clave de `/modelbreaches`

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `starttime` | int (ms) | Timestamp Unix en milisegundos |
| `endtime` | int (ms) | Timestamp Unix en milisegundos |
| `from_time` | string | Fecha legible (`YYYY-MM-DD HH:MM:SS`) |
| `to_time` | string | Fecha legible |
| `minscore` | float | Score mínimo (0-100) |
| `maxscore` | float | Score máximo |
| `did` | int | Filter por device ID |
| `pbid` | int | Breach específico por ID |
| `includeacknowledged` | bool | Incluir breaches acknowledged |
| `includesuppressed` | bool | Incluir breaches suprimidos |
| `minimal` | bool | Reducir payload |
| `expandenums` | bool | Convertir enums numéricos a texto |
| `count` | int | Limitar número de resultados |
| `responsedata` | string | Restringir campos devueltos |

### Lo que asume el código actual
- `/api/v1/alerts` (no existe)
- `/api/v1/modelbreaches` (ruta incorrecta: es `/modelbreaches`)
- `/api/v1/devices` (ruta incorrecta: es `/devices`)

### ❌ Discrepancia: CRÍTICA
Los endpoints del código tienen un prefijo `/api/v1/` que no existe en la API real. Las rutas correctas son `/modelbreaches`, `/devices`, etc.

---

## 3. Formato de Datos

### Formato: JSON exclusivamente
No hay exportación CSV o syslog nativa vía API.

### Estructura de Model Breach (objeto principal para KhaiNet)
```json
{
  "pbid": 12345,
  "score": 85.5,
  "time": 1641038400000,
  "acknowledged": false,
  "suppressed": false,
  "model": {
    "name": "Device / Anomalous Connection / External Destination",
    "uuid": "12345678-1234-1234-1234-123456789012",
    "pid": 67
  },
  "device": {
    "did": 123,
    "hostname": "server01",
    "ip": "192.168.1.100"
  },
  "connectionDetails": {},
  "url": "https://darktrace.instance/modelbreaches/12345"
}
```

### Discrepancias con el código actual

| Campo | Código asume | API real | Impacto |
|-------|-------------|----------|---------|
| `score` | Float 0-1 | Float 0-100 | Normalización necesaria |
| `time` | ISO8601 string | Unix timestamp (ms) | Parsing diferente |
| `model` | String | Objeto `{name, uuid, pid}` | Acceso anidado |
| `pbid` | String | Integer | Tipo diferente |
| `device.ip` | IP directa | IP directa (pero necesita seudonimización) | OK |

---

## 4. Rate Limits / Límites de Volumen

### Lo que se sabe
- La API devuelve **HTTP 429 (Too Many Requests)** cuando se excede el rate limit
- No hay documentación pública con cifras concretas (peticiones/minuto, etc.)
- Los rate limits parecen ser **por instancia/appliance** y dependen de la carga del sistema

### Paginación
- **No hay paginación tipo cursor**. Se usan parámetros `count` + `offset` manualmente
- El parámetro `responsedata` permite restringir campos devueltos para reducir payload
- `minimal=true` reduce datos devueltos en model breaches

### Lo que asume el código actual
- Paginación cursor-based con `next_cursor` (no existe)
- Rate limit de 10 req/s (no documentado, podría ser diferente)

### ❌ Discrepancia: ALTA
El mecanismo de paginación es completamente diferente. El código busca `next_cursor` en la respuesta, que no existe. Hay que implementar paginación manual con `count` + `offset`.

---

## 5. Acceso Histórico vs Tiempo Real

### Consultas históricas: ✅ SÍ soportadas

**Dos formatos de tiempo aceptados:**

| Formato | Parámetros | Ejemplo |
|---------|-----------|---------|
| Unix timestamp (ms) | `starttime`, `endtime` | `starttime=1640995200000&endtime=1641081600000` |
| Human-readable | `from_time`, `to_time` | `from_time=2024-01-01 10:00:00&to_time=2024-01-01 18:00:00` |

> ⚠️ Los parámetros de tiempo deben ir en pares (starttime+endtime o from_time+to_time).

### Retención de datos
- **Depende de la configuración del appliance** (capacidad de almacenamiento)
- El endpoint `/status` devuelve `storage_status.data_retention_days`
- Típicamente: **30-90 días** según almacenamiento y tráfico
- Los datos de red crudos (advanced search) tienen menor retención que las alertas

### ⚠️ CRÍTICO para shadow mode de 12 meses
Con retención típica de 30-90 días, **no se pueden consultar alertas de hace 12 meses** al final del periodo.

**Estrategia recomendada:**
- **Exportar alertas continuamente** (polling cada 5-15 min) y almacenarlas en base de datos propia
- No depender de consultar histórico al final del periodo
- Considerar exportar retroactivamente todo el histórico disponible al inicio del proyecto

### Lo que asume el código actual
- Parámetros `from`/`to` con ISO8601 (incorrectos: son `starttime`/`endtime` o `from_time`/`to_time`)

---

## 6. Licencia

### Lo que se sabe
- Los tokens de API se generan desde el panel de administración (System Config → API Keys)
- La API base (Threat Visualizer) parece estar **incluida en la licencia principal** de Darktrace
- **Endpoints que requieren módulos adicionales:**
  - `/antigena` → Requiere **Darktrace RESPOND** (anteriormente Antigena Network)
  - `/aianalyst/*` → Requiere **Darktrace AI Analyst** (módulo adicional)
  - `/agemail/*` → Requiere **Darktrace EMAIL** (módulo adicional)
  - `saasonly`/`saasfilter` → Requiere **Darktrace SaaS/Cloud Security**
- El endpoint `/status` devuelve `license_info` con tipo de licencia, features habilitadas y límites

### Lo que NO se pudo verificar
- Si la API requiere un add-on específico en todas las licencias o solo en Enterprise
- Si hay límite de tokens API por licencia
- Si hay límite de peticiones API por licencia

> **⚠️ Requiere confirmación del usuario humano**: Verificar con el account manager de Darktrace si la licencia actual incluye acceso API completo y los módulos necesarios.

---

## 7. Documentación Oficial

### URLs conocidas

| Recurso | URL | Acceso |
|---------|-----|--------|
| Customer Portal | `https://customerportal.darktrace.com` | Login requerido |
| Darktrace Docs | `https://docs.darktrace.com` | No accesible públicamente |
| Community | `https://community.darktrace.com` | Login requerido |
| API Guide | "Official Darktrace API Guide" | Disponible vía Customer Portal |

> ⚠️ La documentación oficial de la API de Darktrace **no es pública**. Está detrás del Customer Portal con login. No hay Swagger/OpenAPI público ni Postman collection oficial.

### Fuentes alternativas verificadas (SDKs de comunidad)
- **SDK Python** (LegendEvent/darktrace-sdk): Documentación completa de todos los endpoints
- **SDK Go** (rfizzle/darktrace): Implementación de cliente con auth HMAC
- **Clase Python** (hutchris/darktrace): Implementación mínima de auth

---

## 8. Ejemplo de Implementación Correcta (Python)

```python
import hmac, hashlib, requests, json
from datetime import datetime
from urllib.parse import urlencode

class DarktraceAPI:
    def __init__(self, host, public_token, private_token, verify_ssl=True):
        self.host = host.rstrip("/")
        self.public_token = public_token
        self.private_token = private_token.encode()
        self.session = requests.Session()
        self.verify_ssl = verify_ssl

    def _make_headers(self, path, params):
        sorted_params = dict(sorted(params.items()))
        param_str = urlencode(sorted_params)
        full_path = f"{path}?{param_str}" if param_str else path
        date_str = datetime.utcnow().isoformat(timespec="seconds")
        mac_str = f"{full_path}\n{self.public_token}\n{date_str}".encode()
        signature = hmac.new(self.private_token, mac_str, hashlib.sha1).hexdigest()
        return {
            "DTAPI-Token": self.public_token,
            "DTAPI-Date": date_str,
            "DTAPI-Signature": signature,
            "Content-Type": "application/json"
        }

    def get(self, endpoint, params=None):
        params = params or {}
        path = f"/{endpoint}"
        headers = self._make_headers(path, params)
        url = f"{self.host}{path}"
        response = self.session.get(url, params=params, headers=headers, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()

# Uso
dt = DarktraceAPI("https://darktrace-instance", "pub_token", "priv_token")
breaches = dt.get("modelbreaches", {
    "count": 100,
    "includeacknowledged": "false",
    "minscore": "50",
    "from_time": "2026-07-01 00:00:00",
    "to_time": "2026-07-03 00:00:00",
    "expandenums": "true"
})
```

---

## 9. Limitaciones Conocidas

| Limitación | Detalle | Impacto en KhaiNet |
|-----------|---------|-------------------|
| `/devicesummary` devuelve HTTP 500 con API tokens | Solo funciona con sesión/cookie (browser). Bug confirmado v6.3.18 | No se puede obtener resumen de dispositivo vía API |
| Sin exportación CSV/Syslog nativa | Solo JSON | Post-procesamiento necesario |
| Sin paginación tipo cursor | `count` + `offset` manual | Implementar paginación manual |
| Sin webhooks/push | Solo polling | Polling continuo necesario |
| Rate limits no documentados | HTTP 429 existe pero sin cifras | Backoff exponencial |
| Retención limitada (30-90 días) | No se puede consultar histórico de 12 meses | **CRÍTICO: exportar continuamente** |
| Parámetros ordenados alfabéticamente | Si no van ordenados, devuelve 401 | Usar SDK o implementar correctamente |
| Documentación no pública | Solo Customer Portal | Usar SDK de comunidad como referencia |

---

## 10. Discrepancias entre el código actual y la API real

### Resumen de cambios necesarios en `tuning/src/darktrace_client.py`

| Aspecto | Código actual | API real | Severidad |
|---------|--------------|----------|-----------|
| **Autenticación** | Bearer token único | HMAC-SHA1 con public+private token | 🔴 FATAL |
| **Endpoints** | `/api/v1/alerts`, `/api/v1/modelbreaches` | `/modelbreaches`, `/aianalyst/incidentevents` | 🔴 CRÍTICA |
| **Paginación** | Cursor-based (`next_cursor`) | `count` + `offset` manual | 🟠 ALTA |
| **Parámetros tiempo** | `from`/`to` (ISO8601) | `starttime`/`endtime` (ms) o `from_time`/`to_time` | 🟠 ALTA |
| **Score** | Float 0-1 | Float 0-100 | 🟡 MEDIA |
| **Timestamp** | ISO8601 string | Unix ms (integer) | 🟡 MEDIA |
| **Model field** | String | Objeto `{name, uuid, pid}` | 🟡 MEDIA |
| **Rate limit** | 10 req/s (asumido) | No documentado, HTTP 429 | 🟢 BAJA |

### Lo que el código hace bien (no necesita cambios)
- ✅ Mock mode completo (permite desarrollo sin API)
- ✅ Rate limiting con token bucket
- ✅ Retry con backoff exponencial (tenacity)
- ✅ Seudonimización de IPs (GDPR compliance)
- ✅ Estructura modular y async
- ✅ Manejo de errores con excepciones específicas

---

## 11. Evaluación de Viabilidad para Shadow Mode

### ✅ Viabilidad: ALTA
La API de Darktrace **sí permite exportar alertas de forma programática** con suficiente detalle para entrenar modelos de IA.

### ⚠️ Riesgos clave

1. **Retención de datos (CRÍTICO)**: Con 30-90 días de retención típica, es imposible consultar alertas de hace 12 meses al final del periodo.
   - **Solución**: Exportar continuamente desde el día 1 y almacenar en base de datos propia (PostgreSQL/ClickHouse).

2. **Rate limits desconocidos**: Sin cifras oficiales, existe riesgo de throttling.
   - **Solución**: Backoff exponencial + intervalos de 5-15 min.

3. **Licencia**: Verificar que la licencia actual incluye acceso API completo y los módulos necesarios.
   - **Solución**: Confirmar con account manager de Darktrace.

4. **Sin webhooks**: El polling continuo consume recursos.
   - **Solución**: Script daemon con intervalos configurables.

5. **Cliente API necesita reescritura**: El `darktrace_client.py` actual no funcionará con la API real.
   - **Solución**: Reescribir autenticación, endpoints, paginación y parsing.

### 📋 Recomendaciones de implementación

1. **Usar `darktrace-sdk` (Python)** como referencia: `pip install darktrace-sdk`
2. **Exportar cada 5-10 minutos**: Model breaches + AI Analyst incidents + Antigena actions
3. **Almacenar en PostgreSQL/ClickHouse** con schema que preserve: `pbid`, `score`, `model.uuid`, `model.name`, `device.did`, `device.ip`, `time`, `connectionDetails`
4. **Usar `minimal=true`** para reducir payload en polling frecuente
5. **Usar `expandenums=true`** para obtener strings legibles
6. **Implementar retry con backoff** ante HTTP 429/5xx
7. **Exportar histórico disponible** al inicio del proyecto (todo lo que la retención permita)
8. **Considerar `/advancedsearch`** para obtener datos de red crudos asociados a cada alerta

---

## 12. Plan B: Si no hay API o la licencia no la incluye

### Escenario A: API disponible pero sin módulo AI Analyst
- Usar solo `/modelbreaches` como fuente de etiquetas
- AI Analyst es enriquecimiento opcional, no bloqueante
- El pipeline de tuning funciona con model breaches únicamente

### Escenario B: Sin acceso API
Si la licencia no incluye API, hay tres alternativas:

1. **Export manual desde la UI**:
   - Darktrace permite exportar breaches desde el Threat Visualizer en CSV/JSON
   - Un analista exporta manualmente cada día/semana
   - Los archivos se depositan en un directorio monitorizado
   - El `label_importer.py` se adapta para leer archivos en lugar de la API
   - **Viabilidad**: Media. Labor intensiva pero funcional.

2. **Syslog forwarding**:
   - Darktrace puede configurarse para enviar alertas vía syslog
   - Configurar en System Config → Integrations → Syslog
   - Wazuh o rsyslog recibe los mensajes y los almacena
   - El `label_importer.py` se adapta para parsear syslog
   - **Viabilidad**: Alta. No requiere API, solo configuración de integración.
   - **Limitación**: El formato syslog puede ser menos estructurado que JSON de la API

3. **Etiquetado manual por analistas**:
   - Los analistas revisan alertas de Darktrace y etiquetan eventos de Zeek
   - Usando una herramienta de etiquetado (ej. Label Studio)
   - **Viabilidad**: Baja para 12 meses. Muy labor intensiva.
   - **Uso**: Como complemento, no como fuente principal.

### Recomendación para Plan B
**Syslog forwarding** es la alternativa más robusta si no hay API. Requiere solo configuración en Darktrace (no licencia adicional) y se integra naturalmente con el stack KhaiNet (Wazuh ya está en el stack).

---

## 13. Acción requerida del usuario humano

Para desbloquear este issue, necesitamos que el equipo humano proporcione:

### Preguntas críticas

1. **¿La licencia actual de Darktrace incluye acceso a la API?**
   - Verificar en System Config → API Keys si se pueden generar tokens
   - Si no aparece la opción, contactar al account manager de Darktrace

2. **¿Qué módulos de Darktrace están licenciados?**
   - Threat Visualizer (base) — necesario para `/modelbreaches`
   - AI Analyst — necesario para `/aianalyst/*`
   - RESPOND/Antigena — necesario para `/antigena`
   - EMAIL — necesario para `/agemail/*`

3. **¿Cuál es la URL de la instancia de Darktrace?**
   - Ej: `https://darktrace.empresa.com`

4. **¿Se pueden generar tokens de API?**
   - Si sí, proporcionar `public_token` y `private_token` (por canal seguro)
   - Si no, confirmar si se puede configurar syslog forwarding

5. **¿Cuál es la retención de datos configurada?**
   - Consultar en System Config o vía endpoint `/status`
   - Esto determina cuánto histórico se puede exportar retroactivamente

6. **¿Hay restricciones de red/firewall para acceder a la API?**
   - ¿La instancia es accesible desde la red donde se desplegará KhaiNet?

### Cómo verificar rápidamente
```bash
# Si tienen acceso a la instancia de Darktrace:
# 1. Login como admin
# 2. Ir a System Config → API Keys
# 3. Si pueden generar tokens → la API está disponible
# 4. Generar un par de tokens y probar:
curl -X GET "https://darktrace.empresa.com/status" \
  -H "DTAPI-Token: PUBLIC_TOKEN" \
  -H "DTAPI-Date: 2026-07-03T10:00:00" \
  -H "DTAPI-Signature: COMPUTED_SIGNATURE" \
  -H "Content-Type: application/json"
# El endpoint /status devuelve info de licencia y retención
```

---

## Fuentes

| Fuente | URL | Tipo |
|--------|-----|------|
| Darktrace SDK Python (LegendEvent) | https://github.com/LegendEvent/darktrace-sdk | SDK + docs completas |
| Darktrace SDK Go (rfizzle) | https://github.com/rfizzle/darktrace | SDK Go |
| Darktrace API handler (hutchris) | https://github.com/hutchris/darktrace | Implementación auth Python |
| Darktrace API (Alexey223) | https://github.com/Alexey223/DarktraceAPI | Implementación Python |
| Darktrace Scripts (CarlosMarrez) | https://github.com/CarlosMarrez/darktrace | Scripts de API |
| Darktrace Customer Portal | https://customerportal.darktrace.com | Documentación oficial (login) |

---

## Conclusión

La API de Darktrace **existe, es viable y permite exportar alertas** con el detalle necesario para el shadow mode. Sin embargo:

1. **El cliente API actual (`darktrace_client.py`) necesita reescritura** — la autenticación, endpoints, paginación y formato de datos son todos diferentes a lo asumido.
2. **La estrategia de shadow mode debe modificarse** — la retención limitada (30-90 días) exige exportación continua desde el día 1, no consulta histórica al final.
3. **Se requiere confirmación humana** sobre licencia, módulos y credenciales antes de proceder.
4. **Hay un Plan B viable** (syslog forwarding) si la API no está disponible en la licencia actual.
