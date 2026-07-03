# KhaiNet Detection Module

Baseline de tráfico y modelos de detección de anomalías para KhaiNet.

## Objetivo

Implementar los 3 modelos de detección de anomalías de KhaiNet usando datos
sintéticos y mock mode, listo para conectar a infraestructura real (Zeek,
OpenSearch) cuando esté desplegada.

## Modelos de Detección

| Modelo | Librería | Input | Output |
|--------|----------|-------|--------|
| **Isolation Forest** | scikit-learn | FeatureVector (17 features) | Score 0-1 |
| **Autoencoder** | PyTorch | FeatureVector (17 features) | Score 0-1 (reconstruction error) |
| **HMM** | hmmlearn | WindowFeatures (5 features, 5-min windows) | Score 0-1 + state label |

## Arquitectura

```
Zeek logs (conn, dns, http, ssl)
        ↓
zeek_parser.py → Pydantic models (pseudonymized IPs)
        ↓
feature_engineering.py
  ├── extract_event_features() → FeatureVector[] (for IF, AE)
  └── extract_window_features() → WindowFeatures[] (for HMM)
        ↓
normalize_features() (StandardScaler)
        ↓
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Isolation Forest│  │   Autoencoder   │  │      HMM        │
│   (sklearn)     │  │   (PyTorch)     │  │  (hmmlearn)     │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ↓
                    orchestrator.py
              ModelResult[] (individual scores)
              + BaselineCalculator
              + HMM StateMapping
                              ↓
                    tuning/ module
              (score fusion + threshold tuning)
```

## Módulos

| Módulo | Descripción |
|--------|-------------|
| `models.py` | Modelos Pydantic v2 (ZeekConn, ZeekDNS, FeatureVector, etc.) |
| `zeek_parser.py` | Parser de logs TSV de Zeek |
| `feature_engineering.py` | Extracción y normalización de features |
| `isolation_forest.py` | Modelo Isolation Forest (scikit-learn) |
| `autoencoder.py` | Autoencoder denso (PyTorch), umbral p99 |
| `hmm_detector.py` | HMM con hmmlearn, 4 estados, mapeo post-entrenamiento |
| `baseline.py` | Baseline estadístico por host/servicio |
| `orchestrator.py` | Orquestador del pipeline de los 3 modelos |
| `model_persister.py` | Persistencia de modelos (joblib, torch, JSON) |
| `synthetic_data.py` | Generador de logs Zeek sintéticos |

## HMM State Mapping

Los estados del HMM son **no supervisados** — no se asume el orden. El mapeo
a etiquetas semánticas (normal, scan, exfil, c2) se hace en post-procesamiento:

- Estado con menor bytes_out y menos destinos → **normal**
- Estado con más destinos únicos → **scan**
- Estado con bytes_out más alto → **exfil**
- Estado restante → **c2**

## Uso

```python
from src.orchestrator import DetectionOrchestrator
from src.synthetic_data import generate_all_logs

# Generate synthetic data
data = generate_all_logs(seed=42)

# Initialize and train
orch = DetectionOrchestrator()
orch.train_all(data["conn"], data["dns"], data["http"], data["ssl"])

# Detect anomalies
results = orch.detect(data["conn"], data["dns"], data["http"], data["ssl"])

# Save models
orch.save_models("./models")

# Load models
new_orch = DetectionOrchestrator()
new_orch.load_models("./models")
```

## Patrones Seguidos

Este módulo sigue los mismos patrones que `brain/` y `tuning/`:

- `from __future__ import annotations` en todos los archivos
- Pydantic v2 con `ConfigDict(extra="ignore")`
- structlog para logging
- Validador de timestamp `_parse_timestamp` (datetime, ISO-8601, epoch)
- IPs seudonimizadas con SHA-256+sal
- conftest.py con `sys.path.insert`
- Tests con pytest, datos sintéticos con seed
- `__init__.py` con `__version__`
- Mock mode con flag en config
- Type hints completos

## Tests

```bash
cd /workspace/detection && python -m pytest tests/ -v
```

216 tests cubriendo:
- Parseo de logs Zeek (conn, dns, http, ssl)
- Feature engineering (evento, ventana, normalización)
- Isolation Forest (fit, predict, feature importance)
- Autoencoder (fit, predict, umbral p99, reconstruction error)
- HMM (fit, predict, mapeo de estados, secuencias)
- Baseline (cálculo, percentiles, comparación, serialización)
- Model persister (save/load individual y batch)
- Orchestrator (train all, detect, save/load)
- Integration (pipeline completo end-to-end)
- Models (validación Pydantic, timestamps, seudonimización)

## Configuración

Ver `config/detection_config.yaml` para todos los parámetros configurables.

## Dashboards

- `dashboards/traffic_dashboard.json` — Tráfico general
- `dashboards/anomaly_dashboard.json` — Anomalías por modelo
- `dashboards/baseline_dashboard.json` — Baseline y desviaciones
