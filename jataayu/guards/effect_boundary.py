"""
Jataayu Effect Boundary — authorize at the action, not the text
===============================================================
Pattern/classifier guards (jataayu's inbound engine, Prompt-Guard, etc.) defend *the attack
string*. The literature is unanimous that this is the weakest tier against adaptive attackers: a
trivial transform defeats string detection ~100% of the time. The durable defenses
(CaMeL — arXiv 2503.18813; FIDES — 2505.23643; arXiv:2606.09549) move the security boundary
off the text and onto the **action**: an attacker who wins the text battle still must not be able
to COMMIT an unauthorized high-effect action.

This module implements that boundary deterministically (no LLM in the decision path):

  1. Provenance-typed values. Data read by the agent is wrapped with a provenance label
     (TRUSTED / UNTRUSTED). Provenance flows into the actions those values drive.

  2. PREVIEW -> COMMIT. `preview()` produces a canonical, normalized description of the exact
     request plus a deterministic policy decision (ALLOW / DENY / NEEDS_APPROVAL) based on
     (effect severity x worst inbound provenance x the agent's capability policy). A `commit_token`
     is issued only on ALLOW, bound to the canonical request. `commit()` runs the executor only if
     the token validates against the action actually being executed — so mutating the action after
     authorization (a classic injection trick) yields a hash mismatch and is rejected.

  3. Read-boundary confinement. `confine_read()` replaces a raw sensitive read with an opaque
     handle + a bounded summary. The agent/LLM context only ever holds the handle, so an injected
     "exfiltrate the secret" instruction has nothing but a handle to send; only the trusted
     executor can dereference it at commit time.

It composes with `jataayu.config.policy.AgentPolicy` (capability allow/forbid lists) but works
standalone with safe defaults.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional

from jataayu.core.taint import (
    _SHELL_SINK_TOOLS, _FILE_WRITE_TOOLS, _NETWORK_TOOLS, _SECRET_TOOLS,
)


class Provenance(Enum):
    """Where a value came from, for authorization purposes."""
    TRUSTED = "trusted"      # first-party: the operator, system config, signed sources
    UNTRUSTED = "untrusted"  # anything attacker-influenceable: web, issues, tool returns, memory

    def worst(self, other: "Provenance") -> "Provenance":
        return Provenance.UNTRUSTED if Provenance.UNTRUSTED in (self, other) else Provenance.TRUSTED


class EffectClass(Enum):
    """The kind of effect an action has, ordered by severity."""
    NONE = "none"
    READ = "read"
    MEMORY_WRITE = "memory_write"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    SECRET_READ = "secret_read"
    SHELL = "shell"
    CODE_EVAL = "code_eval"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @property
    def capability(self) -> Optional[str]:
        """The capability tag (matching AgentPolicy) this effect requires, if any."""
        return _EFFECT_CAPABILITY.get(self)


_SEVERITY = {
    EffectClass.NONE: 0,
    EffectClass.READ: 1,
    EffectClass.MEMORY_WRITE: 2,
    EffectClass.FILE_WRITE: 3,
    EffectClass.NETWORK: 4,
    EffectClass.SECRET_READ: 4,
    EffectClass.SHELL: 5,
    EffectClass.CODE_EVAL: 5,
}

_EFFECT_CAPABILITY = {
    EffectClass.READ: "fs_read",
    EffectClass.MEMORY_WRITE: "memory_write",
    EffectClass.FILE_WRITE: "fs_write",
    EffectClass.NETWORK: "network_write",
    EffectClass.SECRET_READ: "reads_secrets",
    EffectClass.SHELL: "exec",
    EffectClass.CODE_EVAL: "exec",
}

# Effects for which untrusted-derived input is categorically denied (no preview->commit at all):
# committing them under attacker influence is the kill-chain endpoint.
_CRITICAL_EFFECTS = frozenset({EffectClass.SHELL, EffectClass.CODE_EVAL, EffectClass.SECRET_READ})
# Effects for which untrusted-derived input requires human approval rather than an outright deny.
_APPROVAL_EFFECTS = frozenset({EffectClass.NETWORK, EffectClass.FILE_WRITE, EffectClass.MEMORY_WRITE})

_CODE_EVAL_TOOLS = frozenset({"eval", "exec", "python_eval", "js_eval", "run_code", "code_interpreter"})
_MEMORY_WRITE_TOOLS = frozenset({"memory_write", "save_memory", "remember", "store_memory", "kv_set"})


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class CommitRejected(Exception):
    """Raised when commit() is called on an action that was not authorized by its preview."""


@dataclass
class Value:
    """A piece of data flowing into an action, tagged with its provenance."""
    data: Any
    provenance: Provenance = Provenance.UNTRUSTED
    source: str = "unknown"


@dataclass
class OpaqueHandle:
    """A reference to confined sensitive content. The raw value never enters agent context."""
    handle_id: str
    summary: str
    source: str

    def __str__(self) -> str:
        return f"<jataayu:handle:{self.handle_id} {self.summary}>"


@dataclass
class PreviewResult:
    tool_name: str
    params: dict
    effect_class: EffectClass
    provenance: Provenance
    decision: Decision
    reason: str
    canonical: str
    commit_token: Optional[str] = None
    violations: list[str] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "effect_class": self.effect_class.value,
            "provenance": self.provenance.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "violations": self.violations,
            "commit_token": self.commit_token,
        }


def _canonical(tool_name: str, params: dict) -> str:
    """Deterministic, normalized serialization of an action for binding the commit token."""
    return json.dumps({"tool": tool_name.strip().lower(), "params": params},
                      sort_keys=True, separators=(",", ":"), default=str)


class EffectBoundary:
    """
    Deterministic action-level authorization with PREVIEW -> COMMIT and read confinement.

    Example::

        boundary = EffectBoundary(policy=agent_policy)

        # Untrusted content extracted from a web page wants to run a shell command:
        pv = boundary.preview("bash", {"command": cmd},
                              values=[Value(cmd, Provenance.UNTRUSTED, source="web-page")])
        if pv.approved:
            boundary.commit(pv, {"command": cmd}, lambda: run(cmd))
        else:
            log(pv.reason)   # DENY — untrusted data may not reach a shell, regardless of text
    """

    def __init__(self, policy=None, *, default_untrusted: bool = True):
        self.policy = policy
        self.default_untrusted = default_untrusted
        self._vault: dict[str, str] = {}
        self._counter = 0

    # -- effect classification -------------------------------------------------
    def classify(self, tool_name: str) -> EffectClass:
        t = tool_name.strip().lower()
        if t in _CODE_EVAL_TOOLS:
            return EffectClass.CODE_EVAL
        if t in _SHELL_SINK_TOOLS:
            return EffectClass.SHELL
        if t in _SECRET_TOOLS:
            return EffectClass.SECRET_READ
        if t in _MEMORY_WRITE_TOOLS:
            return EffectClass.MEMORY_WRITE
        if t in _FILE_WRITE_TOOLS:
            return EffectClass.FILE_WRITE
        if t in _NETWORK_TOOLS:
            return EffectClass.NETWORK
        return EffectClass.READ

    # -- the policy decision (deterministic, no LLM) ---------------------------
    def _decide(self, effect: EffectClass, provenance: Provenance) -> tuple[Decision, str, list[str]]:
        violations: list[str] = []

        # 1. Capability isolation from the agent policy always wins.
        cap = effect.capability
        if cap and self.policy is not None and not self.policy.is_capability_allowed(cap):
            violations.append(cap)
            return Decision.DENY, f"capability '{cap}' is forbidden for this agent", violations

        # 2. Untrusted-derived input into a consequential effect.
        if provenance is Provenance.UNTRUSTED:
            if effect in _CRITICAL_EFFECTS:
                return (Decision.DENY,
                        f"untrusted-derived input may not reach a {effect.value} effect", violations)
            if effect in _APPROVAL_EFFECTS:
                return (Decision.NEEDS_APPROVAL,
                        f"untrusted-derived {effect.value} effect requires human approval", violations)

        # 3. Trusted input, or low-severity effect.
        return Decision.ALLOW, f"{provenance.value} input into {effect.value} effect", violations

    # -- preview / commit ------------------------------------------------------
    def preview(self, tool_name: str, params: dict,
                values: Iterable[Value] = ()) -> PreviewResult:
        effect = self.classify(tool_name)
        provs = [v.provenance for v in values]
        if provs:
            provenance = provs[0]
            for p in provs[1:]:
                provenance = provenance.worst(p)
        else:
            provenance = Provenance.UNTRUSTED if self.default_untrusted else Provenance.TRUSTED

        decision, reason, violations = self._decide(effect, provenance)
        canonical = _canonical(tool_name, params)
        token = None
        if decision is Decision.ALLOW:
            token = hashlib.sha256(canonical.encode()).hexdigest()

        return PreviewResult(
            tool_name=tool_name, params=params, effect_class=effect, provenance=provenance,
            decision=decision, reason=reason, canonical=canonical,
            commit_token=token, violations=violations,
        )

    def commit(self, preview: PreviewResult, params: dict, executor: Callable[[], Any]) -> Any:
        """
        Execute `executor` iff `preview` authorized exactly this action.

        Rejects when: the preview was not ALLOW, no token was issued, or the action's canonical
        form changed since preview (an attacker mutating the call after authorization).
        """
        if preview.decision is not Decision.ALLOW or not preview.commit_token:
            raise CommitRejected(f"not authorized: {preview.decision.value} — {preview.reason}")
        expected = hashlib.sha256(_canonical(preview.tool_name, params).encode()).hexdigest()
        if expected != preview.commit_token:
            raise CommitRejected("action was mutated after authorization (commit token mismatch)")
        return executor()

    # -- read-boundary confinement ---------------------------------------------
    def confine_read(self, content: str, source: str, *, summary: Optional[str] = None) -> OpaqueHandle:
        """Store sensitive content out of agent context, returning an opaque handle + summary."""
        self._counter += 1
        digest = hashlib.sha256(f"{self._counter}:{content}".encode()).hexdigest()[:12]
        if summary is None:
            summary = f"{len(content)} chars from {source}"
        self._vault[digest] = content
        return OpaqueHandle(handle_id=digest, summary=summary, source=source)

    def dereference(self, handle: OpaqueHandle) -> Optional[str]:
        """Resolve a handle back to raw content — for the trusted executor at commit time only."""
        return self._vault.get(handle.handle_id)
