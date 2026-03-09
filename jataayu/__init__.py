"""
Jataayu — LLM-backed AI agent security.

Inbound injection detection + outbound privacy protection.

Quick start::

    from jataayu import jataayu_check_inbound, jataayu_check_outbound

    # Check external content for injection attacks
    result = jataayu_check_inbound(content, surface="github-issue")

    # Check outbound content for privacy leaks
    result = jataayu_check_outbound(draft, surface="discord-channel")

    # Short aliases also available:
    status, findings = check_inbound(content, surface="github-issue")
    status, redacted = check_outbound(draft, surface="discord-channel")
"""
__version__ = "0.2.0"

from jataayu.core.threat import ThreatResult, ThreatLevel, ThreatType
from jataayu.guards.inbound import InboundGuard
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig
from jataayu.api import jataayu_check_inbound, jataayu_check_outbound
from jataayu.convenience import check_inbound, check_outbound

__all__ = [
    # Public convenience API (dict return format)
    "jataayu_check_inbound",
    "jataayu_check_outbound",
    # Short aliases (tuple return format)
    "check_inbound",
    "check_outbound",
    # Core classes (for advanced usage)
    "ThreatResult",
    "ThreatLevel",
    "ThreatType",
    "InboundGuard",
    "OutboundGuard",
    "PrivacyConfig",
]
