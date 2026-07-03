"""KhaiNet Tuning — Model threshold tuning with multi-source auto-labeling.

Ajusta los umbrales de los 3 modelos de detección de anomalías de KhaiNet
(Isolation Forest, Autoencoder, HMM) usando un sistema de auto-etiquetado
multi-fuente con weak supervision y active learning.

## Arquitectura

### Sistema de auto-etiquetado (sin dependencia de Darktrace)

Cuando Darktrace no está disponible (entorno aislado), el sistema se
calibra a sí mismo usando múltiples fuentes internas:

1. **Label sources** (`label_sources/`): cada fuente convierte alertas raw
   en WeakLabels con confianza:
   - Suricata (firmas, alta confianza)
   - Wazuh (HIDS, confianza media-alta)
   - MISP (threat intel, alta confianza)
   - Brain (correlación IA MITRE ATT&CK, confianza media)
   - Analyst (feedback humano, confianza máxima)
   - Darktrace (opcional, cuando disponible)

2. **Weak supervisor** (`weak_supervisor.py`): combina los votos de
   múltiples fuentes ponderadamente (estilo Snorkel). El analista
   siempre tiene override.

3. **Active learning** (`active_learning.py`): selecciona los eventos
   más inciertos para que el analista los revise. Sus etiquetas se
   incorporan como ground truth de máxima confianza.

4. **Threshold tuner** (`threshold_tuner.py`): optimiza umbrales con
   etiquetas ponderadas por confianza (cost-weighted, FN 10× FP).

### Pipeline end-to-end

    Eventos → Label sources → Weak supervision → Consensus labels
    → Temporal alignment → Weighted threshold tuning → Active learning
    → Analyst feedback → Re-tune (ciclo iterativo)

### Modo Darktrace (opcional)

Cuando Darktrace está disponible, funciona como una fuente más en el
weak supervisor (con peso alto). El sistema puede operar con o sin él.
"""

__version__ = "2.0.0"
