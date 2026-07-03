"""KhaiNet Brain — Correlation and reasoning engine.

Capa 5 del pipeline KhaiNet: recibe alertas pre-filtradas de modelos ML,
Suricata y Wazuh, las correlaciona, enriquece, puntúa y explica usando un LLM,
y produce incidentes que se envían a Shuffle (SOAR).
"""

__version__ = "1.0.0"
