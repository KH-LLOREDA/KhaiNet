"""KhaiNet Pipeline — Kafka bus between sensors, detection, and tuning.

This module is the integration layer that connects:
- Sensor simulator → Kafka topics (zeek-*, suricata-alerts, wazuh-events)
- Kafka zeek-* topics → detection/ orchestrator → ml-scores topic
- Kafka suricata/wazuh/ml-scores → tuning/ label sources → brain-incidents
"""

__version__ = "1.0.0"
