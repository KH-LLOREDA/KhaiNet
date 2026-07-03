"""Label sources for the KhaiNet auto-labeling system.

Each source converts raw alerts/events from a detection component into
WeakLabel objects that the WeakSupervisor can combine.

Available sources:
- SuricataLabeler: signature-based alerts (EVE JSON)
- WazuhLabeler: host-based intrusion detection alerts
- MISPLabeler: threat intelligence indicators (IOCs)
- BrainLabeler: AI correlation with MITRE ATT&CK mapping
- AnalystLabeler: human analyst feedback (active learning)
- DarktraceLabeler: Darktrace alerts (optional, when available)
"""

from src.label_sources.analyst_labeler import AnalystLabeler
from src.label_sources.base import LabelSource
from src.label_sources.brain_labeler import BrainLabeler
from src.label_sources.darktrace_labeler import DarktraceLabeler
from src.label_sources.misp_labeler import MISPLabeler
from src.label_sources.suricata_labeler import SuricataLabeler
from src.label_sources.wazuh_labeler import WazuhLabeler

__all__ = [
    "LabelSource",
    "SuricataLabeler",
    "WazuhLabeler",
    "MISPLabeler",
    "BrainLabeler",
    "AnalystLabeler",
    "DarktraceLabeler",
]
