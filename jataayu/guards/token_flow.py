
"""
TokenFlow guard — borrowed from Token-Flow Firewall (arXiv:2607.08395) Episode 21

This is the flow-level primitive that sits BEFORE EffectBoundary.

Concept: don't just gate the final tool call; audit the token flow (memory update,
tool arg, file content, skill def) from source to sink with structured provenance.

Maps to Jataayu's surface-integrity positioning:
  source_surface (e.g. github-issue/web-page/dm/group-chat/memory-recall)
  -> sink_type (file_write/memory_write/skill_write/network/outbound/shell)
  with audience, durability, trust labels carried.

Borrowed ideas:
  1. Source->Sink audit record (not just provenance enum)
  2. Memory as privileged sink (persistence amplifier)
  3. Skills as persistence amplifier (skill_write = privileged)
  4. Boundary-aware escalation: fast local check, selective LLM arbitration with full record
  5. Flow lineage chainable across turns for SessionTrace

Current implementation = Slice 1 deterministic only (no LLM deps).
Mirrors EffectBoundary decision for backward compat but produces richer audit.

Usage:
    from jataayu.guards.token_flow import TokenFlow, TokenFlowGuard
    guard = TokenFlowGuard()
    flow = TokenFlow(source_surface="github-issue", source_provenance=Provenance.UNTRUSTED,
                     content_preview="... ", content_hash="...", sink_type="memory_write",
                     sink_surface="memory", turn=2)
    decision = guard.audit_flow(flow)
    if decision.decision == Decision.DENY: block
"""
from __future__ import annotations
import hashlib, uuid, json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from jataayu.guards.effect_boundary import Provenance, EffectClass, Decision, EffectBoundary

# Reuse classifier from EffectBoundary for effect severity mapping
_CLASSIFIER = EffectBoundary()

class FlowRisk(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

_SINK_SEVERITY = {
    "read": 1,
    "memory_write": 3,
    "file_write": 4,
    "skill_write": 4,       # NEW: persistence amplifier (borrowed)
    "automation_write": 4,  # NEW: covers automations.yaml, etc.
    "network": 4,
    "secret_read": 5,
    "shell": 5,
    "code_eval": 5,
    "outbound": 3,
}

@dataclass
class TokenFlow:
    """Structured source->sink audit record (borrowed from TokenWall)."""
    flow_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    source_type: str = "unknown"               # e.g. "web-page", "tool-return", "memory-recall", "dm"
    source_provenance: Provenance = Provenance.UNTRUSTED
    source_surface: str = "unknown"            # maps to surfaces/profiles.py
    source_audience: str = "private"           # Jataayu extension: who owned source context
    content_preview: str = ""                  # first 300 chars, never raw secret
    content_hash: str = ""                     # sha256 of full content for lineage
    sink_type: str = "file_write"              # see _SINK_SEVERITY keys
    sink_surface: str = "unknown"
    sink_audience: str = "self"                # Jataayu extension: who will see / be affected
    sink_privilege: int = 0                    # computed from _SINK_SEVERITY if 0
    turn: int = 0
    session_id: str = "session"
    source_flow_ids: list[str] = field(default_factory=list)  # lineage for sleeper detection
    semantic_score: float = 0.0
    audit_record: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.sink_privilege:
            self.sink_privilege = _SINK_SEVERITY.get(self.sink_type, 2)
        if not self.content_hash and self.content_preview:
            self.content_hash = hashlib.sha256(self.content_preview.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "source_type": self.source_type,
            "source_provenance": self.source_provenance.value,
            "source_surface": self.source_surface,
            "source_audience": self.source_audience,
            "content_preview": self.content_preview[:300],
            "content_hash": self.content_hash,
            "sink_type": self.sink_type,
            "sink_surface": self.sink_surface,
            "sink_audience": self.sink_audience,
            "sink_privilege": self.sink_privilege,
            "turn": self.turn,
            "session_id": self.session_id,
            "source_flow_ids": self.source_flow_ids,
            "semantic_score": self.semantic_score,
        }

@dataclass
class FlowDecision:
    flow: TokenFlow
    decision: Decision
    risk: FlowRisk
    reason: str
    needs_llm_arbitration: bool = False
    effect_class: EffectClass = EffectClass.MEMORY_WRITE
    audit_record: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "flow": self.flow.to_dict(),
            "decision": self.decision.value,
            "risk": self.risk.value,
            "reason": self.reason,
            "needs_llm_arbitration": self.needs_llm_arbitration,
            "effect_class": self.effect_class.value,
            "audit_record": self.audit_record,
        }

class TokenFlowGuard:
    """
    Deterministic flow guard (Slice 1).

    Rules (deterministic, no LLM):
    - CRITICAL sinks (shell, code_eval, secret_read) + UNTRUSTED -> DENY (same as EffectBoundary)
    - PRIVILEGED sinks (file_write, skill_write, automation_write, network, memory_write) + UNTRUSTED
        -> NEEDS_APPROVAL + escalation flag (MEDIUM/HIGH)
    - Cross-surface audience drift: source_audience != sink_audience (e.g. private DM -> group) -> flag for LLM arbitration + risk MEDIUM
    - Low privilege sink (read) or TRUSTED source -> ALLOW

    Future slices: LLM semantic scoring for ambiguous flows.
    """

    CRITICAL_SINKS = {"shell","code_eval","secret_read"}
    PRIVILEGED_SINKS = {"file_write","skill_write","automation_write","network","memory_write","outbound"}

    def audit_flow(self, flow: TokenFlow) -> FlowDecision:
        # Map sink_type to EffectClass for compat
        effect_map = {
            "read": EffectClass.READ,
            "memory_write": EffectClass.MEMORY_WRITE,
            "file_write": EffectClass.FILE_WRITE,
            "skill_write": EffectClass.FILE_WRITE,        # treat as file_write severity for now
            "automation_write": EffectClass.FILE_WRITE,
            "network": EffectClass.NETWORK,
            "secret_read": EffectClass.SECRET_READ,
            "shell": EffectClass.SHELL,
            "code_eval": EffectClass.CODE_EVAL,
            "outbound": EffectClass.NETWORK,
        }
        effect = effect_map.get(flow.sink_type, EffectClass.MEMORY_WRITE)

        is_untrusted = flow.source_provenance is Provenance.UNTRUSTED
        cross_surface = flow.source_surface != flow.sink_surface
        audience_drift = flow.source_audience != flow.sink_audience and flow.source_audience in ("private","dm","direct") and flow.sink_audience in ("group","public","shared")

        audit = flow.to_dict()

        # CRITICAL -> DENY if untrusted
        if is_untrusted and flow.sink_type in self.CRITICAL_SINKS:
            return FlowDecision(
                flow=flow,
                decision=Decision.DENY,
                risk=FlowRisk.HIGH,
                reason=f"untrusted {flow.source_type} from {flow.source_surface} may not reach critical sink {flow.sink_type}",
                needs_llm_arbitration=False,
                effect_class=effect,
                audit_record={**audit, "rule":"critical_sink_untrusted_deny"},
            )

        # Audience drift -> escalation, even if otherwise allowed (surface integrity)
        if audience_drift:
            dec = Decision.NEEDS_APPROVAL if flow.sink_privilege >=3 else Decision.ALLOW
            return FlowDecision(
                flow=flow,
                decision=dec,
                risk=FlowRisk.MEDIUM,
                reason=f"audience drift: source {flow.source_audience}({flow.source_surface}) -> sink {flow.sink_audience}({flow.sink_surface}) — private context crossing to shared surface",
                needs_llm_arbitration=True,
                effect_class=effect,
                audit_record={**audit, "rule":"audience_drift"},
            )

        # Privileged sink + untrusted -> NEEDS_APPROVAL + escalation
        if is_untrusted and flow.sink_type in self.PRIVILEGED_SINKS:
            risk = FlowRisk.HIGH if flow.sink_privilege>=4 else FlowRisk.MEDIUM
            return FlowDecision(
                flow=flow,
                decision=Decision.NEEDS_APPROVAL,
                risk=risk,
                reason=f"untrusted flow {flow.source_type}/{flow.source_surface} to privileged sink {flow.sink_type}/{flow.sink_surface} — requires approval (persistence amplifier check)",
                needs_llm_arbitration=True,
                effect_class=effect,
                audit_record={**audit, "rule":"privileged_sink_untrusted_approval"},
            )

        # Otherwise ALLOW
        return FlowDecision(
            flow=flow,
            decision=Decision.ALLOW,
            risk=FlowRisk.LOW,
            reason=f"{flow.source_provenance.value} {flow.source_type} to {flow.sink_type} low privilege / trusted",
            needs_llm_arbitration=False,
            effect_class=effect,
            audit_record={**audit, "rule":"allow"},
        )
