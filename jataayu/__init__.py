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
__version__ = "0.3.1"

from jataayu.core.threat import ThreatResult, ThreatLevel, ThreatType
from jataayu.guards.inbound import InboundGuard
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig, RecoveryResult
from jataayu.api import (
    jataayu_check_inbound,
    jataayu_check_outbound,
    jataayu_recover_outbound,
    jataayu_check_tool_return,
    jataayu_check_memory_write,
    jataayu_check_memory_read,
    jataayu_vet_skill,
    jataayu_check_skillset,
    jataayu_check_egress,
)
from jataayu.guards.egress import EgressChannelGuard, EgressConfig
from jataayu.guards.skill_vet import SkillVetGuard, SkillVetResult
from jataayu.guards.composition import check_skillset, CompositionRisk
from jataayu.guards.effect_boundary import (
    EffectBoundary, Value, Provenance, EffectClass, Decision, CommitRejected,
)
from jataayu.core.audit import SessionTrace, AuditResult, AuditFinding, AuditRisk, TraceEvent
from jataayu.api import jataayu_authorize_action
from jataayu.convenience import check_inbound, check_outbound

__all__ = [
    # Public convenience API (dict return format)
    "jataayu_check_inbound",
    "jataayu_check_outbound",
    # Send-site recovery: rewrite-to-send instead of refuse-to-send
    "jataayu_recover_outbound",
    "RecoveryResult",
    # Execution-context surfaces (tool returns + persistent memory)
    "jataayu_check_tool_return",
    "jataayu_check_memory_write",
    "jataayu_check_memory_read",
    # Outbound egress / exfiltration-channel guard (EchoLeak / AgentFlayer class)
    "jataayu_check_egress",
    "EgressChannelGuard",
    "EgressConfig",
    # Skill vetting (install-time, LLM-judge)
    "jataayu_vet_skill",
    "SkillVetGuard",
    "SkillVetResult",
    # Compositional skillset analysis
    "jataayu_check_skillset",
    "check_skillset",
    "CompositionRisk",
    # Effect boundary — action-level authorization (PREVIEW -> COMMIT)
    "jataayu_authorize_action",
    "EffectBoundary",
    "Value",
    "Provenance",
    "EffectClass",
    "Decision",
    "CommitRejected",
    # Runtime behavioral auditing — cross-turn trajectory analysis
    "SessionTrace",
    "AuditResult",
    "AuditFinding",
    "AuditRisk",
    "TraceEvent",
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
