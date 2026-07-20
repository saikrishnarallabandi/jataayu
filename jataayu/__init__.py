"""
Jataayu — deterministic action authorization for AI agents.

Inbound injection detection + outbound privacy protection.

Quick start::

    from jataayu import jataayu_check_inbound, jataayu_check_outbound

    # Check external content for injection attacks
    result = jataayu_check_inbound(content, surface="github-issue")

    # Check outbound content for privacy leaks
    result = jataayu_check_outbound(draft, surface="discord-channel")

Every guard has ONE entry point, the `jataayu_*` functions below, all returning a
dict. The older tuple-returning `check_inbound` / `check_outbound` aliases in
`jataayu.convenience` are deprecated wrappers over these; they still import and work
but warn.
"""
__version__ = "0.3.1"

from jataayu.core.errors import SecurityError
from jataayu.core.threat import ThreatResult, ThreatLevel, ThreatType
from jataayu.guards.inbound import InboundGuard
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig, RecoveryResult
from jataayu.api import (
    jataayu_check_inbound,
    jataayu_sanitize_inbound,
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
from jataayu.core.audit import (
    SessionTrace, AuditResult, AuditFinding, AuditRisk, TraceEvent, set_decision_sink,
)
from jataayu.api import jataayu_authorize_action

# Deprecated tuple-returning shims. Importable from the package root because that is
# where they have always been importable from, and removing them would turn a warning
# into an ImportError for the exact callers the shims exist to protect. Deliberately
# absent from __all__: `__all__` documents the canonical surface, and these are not it.
from jataayu.convenience import check_inbound, check_outbound, sanitize_inbound  # noqa: F401

__all__ = [
    # Canonical guard entry points (dict return format)
    "jataayu_check_inbound",
    "jataayu_sanitize_inbound",
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
    # Decision telemetry — one record per decision, to your callback
    "set_decision_sink",
    # Raised by callers when a Jataayu verdict is enforced
    "SecurityError",
    # Core classes (for advanced usage)
    "ThreatResult",
    "ThreatLevel",
    "ThreatType",
    "InboundGuard",
    "OutboundGuard",
    "PrivacyConfig",
]
