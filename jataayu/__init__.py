"""
Jataayu — LLM-backed AI agent security.

Inbound injection detection + outbound privacy protection.

Quick start:
    from jataayu import check_inbound, check_outbound

    status, findings = check_inbound(content, surface="github-issue")
    status, redacted = check_outbound(draft, surface="discord-channel")
"""
__version__ = "0.1.0"

from jataayu.core.threat import ThreatResult, ThreatLevel, ThreatType
from jataayu.guards.inbound import InboundGuard
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig
from jataayu.convenience import check_inbound, check_outbound

__all__ = [
    "ThreatResult",
    "ThreatLevel",
    "ThreatType",
    "InboundGuard",
    "OutboundGuard",
    "PrivacyConfig",
    "check_inbound",
    "check_outbound",
]
