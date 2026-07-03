# KhaiNet Tuning Module

Pipeline de tuning de modelos de detección de anomalías usando etiquetas
supervisadas de Darktrace en **shadow mode**.

## Objetivo

Ajustar los umbrales de los 3 modelos de detección de KhaiNet (Isolation Forest,
Autoencoder, HMM) para que sus predicciones se alineen con las de Darktrace,
usando las alertas de Darktrace como etiquetas supervisadas (ground truth) en
modo *shadow* (sin afectar producción).

## Métricas objetivo

| Métrica | Definición | Objetivo |
|---------|-----------|----------|
| **Cobertura** | TP_KhaiNet / total_incidentes_DT | > 90% |
| **Precisión** | TP_KhaiNet / (TP + FP) | > 85% |
| **Ventaja** | Incidentes que KhaiNet detecta y DT no | ≥ 0 |
| **Latencia** | MTTD KhaiNet vs Darktrace | ± 30% |

## Arquitectura

```
Darktrace API → label_importer → SupervisedLabel[]
                                        ↓
ModelScores[] → temporal_alignment → AlignedEvent[]
                                        ↓
                          threshold_tuner → TuningResult[] (per model)
                                        ↓
                          score_fusion → FusionResult (ensemble)
                                        ↓
                      metrics_calculator → TuningMetrics (4 métricas)
                                        ↓
                      experiment_tracker → experiments/{run_id}.json
                                        ↓
                        drift_checker → re-tuning recommendation
```

## Módulos

| Módulo | Descripción |
|--------|-------------|
| `models.py` | Modelos Pydantic v2 |
| `darktrace_client.py` | Cliente API asíncrono (httpx + tenacity) |
| `label_importer.py` | Importación de etiquetas desde alertas DT |
| `temporal_alignment.py` | Matching etiqueta-evento por ventana temporal |
| `cost_matrix.py` | Matriz de costos (FN 10x más caro que FP) |
| `threshold_tuner.py` | Optimización de umbrales (cost-weighted) |
| `score_fusion.py` | Ensemble de los 3 modelos |
| `metrics_calculator.py` | 4 métricas + matriz de confusión |
| `experiment_tracker.py` | Versionado de experimentos |
| `drift_checker.py` | Detección de drift (PSI, KS, Wasserstein) |
| `synthetic_data.py` | Generador de datos sintéticos para mock mode |

## Mock mode

El módulo funciona completamente en **mock mode** con datos sintéticos. Cuando
la API de Darktrace real esté disponible, cambiar `mock_mode: false` en
`config/tuning_config.yaml`.

## Ejecutar tests

```bash
cd tuning
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/ -v
```

## Convenciones

- Pydantic v2 para modelos
- structlog para logging
- asyncio para operaciones asíncronas
- IPs siempre seudonimizadas (hash SHA-256)
- `from __future__ import annotations` en todos los archivos
- Type hints completos
