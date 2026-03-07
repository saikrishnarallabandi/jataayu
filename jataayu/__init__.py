"""
Jataayu — LLM-backed AI agent security.

Inbound injection detection + outbound privacy protection.
"""
__version__ = "0.1.0"

from jataayu.core.threat import ThreatResult, ThreatLevel, ThreatType
from jataayu.guards.inbound import InboundGuard
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig

__all__ = [
    "ThreatResult",
    "ThreatLevel",
    "ThreatType",
    "InboundGuard",
    "OutboundGuard",
    "PrivacyConfig",
]
