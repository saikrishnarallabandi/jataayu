"""
Jataayu SessionTrace — runtime behavioral auditing across a session
===================================================================
Single-shot guards (inbound scan, per-call effect boundary) see one message or
one tool call at a time. Three separate 2026 findings say that is not enough:

  * **Sleeper memory poisoning** — a payload is written to memory on one turn and
    only triggers a harmful action on a *later* turn. The write and the trigger
    are decoupled in time, so a request-scoped check clears both.
  * **Static-scanner collapse** — self-evolving attacks shed static signals per
    call; only the accumulated *behavior* over the trajectory reveals the harm.
  * **Semantic-vs-effect gap** — the visible text of any single turn can look
    benign while the sequence of effects is an exfiltration.

`SessionTrace` accumulates tool calls for a session and audits the *trajectory*:
it profiles which effect classes were touched and flags cross-turn attack
patterns that no per-call check can see — e.g. an untrusted-influenced secret
read on turn 2 followed by a network write on turn 5 (an exfil chain realized
across turns), or an injection-flagged memory write that later feeds a shell.

Deterministic, no LLM. Reuses `EffectClass` / `Provenance` from the effect
boundary so severity ordering and capability tags stay consistent.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Decision sink — "which decisions did Jataayu make?"
#
# Defined ABOVE the effect_boundary import on purpose: effect_boundary imports
# emit_decision back out of this module, so anything it needs must exist before
# this module's own imports run.
# ---------------------------------------------------------------------------

DecisionSink = Callable[[dict], None]

_sink: Optional[DecisionSink] = None
_capture_content: bool = False


def set_decision_sink(sink: Optional[DecisionSink], *, capture_content: bool = False) -> None:
    """Install a process-wide callback receiving one dict per Jataayu decision.

    The sink is telemetry: it can never change a verdict. Exceptions raised inside it
    are caught and logged once to the 'jataayu' logger, never propagated.

    capture_content=False (default) emits metadata only. True includes tool params /
    scanned text. Opt in explicitly — decision records are frequently shipped off-host.

    Pass sink=None to uninstall.

    Record keys map onto NeMo Guardrails' vocabulary as::

        jataayu             NeMo
        -------             ----
        rail_type           rail.type
        decision            rail.status (what was enforced)
        reason              rail.reason
        tool_name           action.name

    Flat snake_case keys, not dotted, so a CSV/DB/Slack emitter needs no re-modelling.
    """
    global _sink, _capture_content
    _sink = sink
    _capture_content = capture_content


def capture_content_enabled(override: Optional[bool] = None) -> bool:
    """Resolve capture_content: per-instance override, else the module-level setting."""
    return _capture_content if override is None else override


def emit_decision(record: dict, sink: Optional[DecisionSink] = None) -> None:
    """Deliver `record` to `sink` (per-instance) or the module-level sink. Never raises.

    A broken telemetry callback must never be why a `deny` fails to reach the caller,
    so every exception is swallowed and logged.
    """
    target = sink if sink is not None else _sink
    if target is None:
        return
    try:
        target(record)
    except Exception:
        logging.getLogger("jataayu").exception("decision sink raised; record dropped")


from jataayu.guards.effect_boundary import EffectBoundary, EffectClass, Provenance  # noqa: E402

# One shared classifier instance (its vault stays empty — we only use classify()).
_CLASSIFIER = EffectBoundary()

# Memory-read tool names (the recall side; the write side lives in effect_boundary).
_MEMORY_READ_TOOLS = frozenset({
    "memory_read", "recall", "load_memory", "get_memory", "kv_get", "search_memory",
})

# Effects that terminate a kill chain — where exfiltrated/poisoned data does harm.
_DANGEROUS_EFFECTS = frozenset({
    EffectClass.SHELL, EffectClass.CODE_EVAL, EffectClass.NETWORK, EffectClass.FILE_WRITE,
})
_EGRESS_EFFECTS = frozenset({EffectClass.NETWORK, EffectClass.FILE_WRITE})


class AuditRisk(Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __lt__(self, other):
        order = [AuditRisk.CLEAN, AuditRisk.LOW, AuditRisk.MEDIUM, AuditRisk.HIGH]
        return order.index(self) < order.index(other)


@dataclass
class TraceEvent:
    """One recorded tool call in a session trajectory."""
    index: int
    turn: int
    tool_name: str
    effect_class: EffectClass
    provenance: Provenance
    inbound_flagged: bool = False   # was this call's input / the tool return flagged by a guard?
    is_memory_read: bool = False
    is_memory_write: bool = False
    summary: str = ""

    @property
    def untrusted(self) -> bool:
        return self.provenance is Provenance.UNTRUSTED

    def to_dict(self) -> dict:
        return {
            "index": self.index, "turn": self.turn, "tool_name": self.tool_name,
            "effect_class": self.effect_class.value, "provenance": self.provenance.value,
            "inbound_flagged": self.inbound_flagged,
            "is_memory_read": self.is_memory_read, "is_memory_write": self.is_memory_write,
            "summary": self.summary,
        }


@dataclass
class AuditFinding:
    """A cross-turn risk pattern surfaced by the trajectory auditor."""
    pattern: str
    risk: AuditRisk
    explanation: str
    event_indices: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern, "risk": self.risk.value,
            "explanation": self.explanation, "event_indices": self.event_indices,
        }


@dataclass
class AuditResult:
    risk: AuditRisk
    findings: list[AuditFinding]
    capability_profile: dict[str, int]   # effect_class value -> count
    event_count: int

    @property
    def is_clean(self) -> bool:
        return self.risk in (AuditRisk.CLEAN, AuditRisk.LOW)

    def to_dict(self) -> dict:
        return {
            "risk": self.risk.value,
            "findings": [f.to_dict() for f in self.findings],
            "capability_profile": self.capability_profile,
            "event_count": self.event_count,
        }


class SessionTrace:
    """
    Accumulates tool calls for one session and audits the trajectory.

    Example::

        trace = SessionTrace(session_id="thread-42")
        trace.record("web.fetch", provenance=Provenance.UNTRUSTED)          # turn 1
        trace.record("read_secret", untrusted=True, turn=2)                 # turn 2
        trace.record("http.post", untrusted=True, turn=5)                   # turn 5
        result = trace.audit()
        if not result.is_clean:
            for f in result.findings:
                log.warning(f.explanation)
    """

    def __init__(self, session_id: str = "session"):
        self.session_id = session_id
        self.events: list[TraceEvent] = []
        self._auto_turn = 0

    # -- recording --------------------------------------------------------
    def record(
        self,
        tool_name: str,
        *,
        params: Optional[dict] = None,
        provenance: Optional[Provenance] = None,
        untrusted: Optional[bool] = None,
        effect_class: Optional[EffectClass] = None,
        inbound_flagged: bool = False,
        turn: Optional[int] = None,
        summary: str = "",
    ) -> TraceEvent:
        """
        Append a tool call to the trajectory.

        Provenance may be given directly (`provenance=`) or as `untrusted=True/False`.
        If neither is supplied, the call is treated as UNTRUSTED (safe default).
        `turn` auto-increments when omitted. `effect_class` is inferred from the
        tool name when omitted.
        """
        if provenance is None:
            if untrusted is None:
                provenance = Provenance.UNTRUSTED
            else:
                provenance = Provenance.UNTRUSTED if untrusted else Provenance.TRUSTED

        if effect_class is None:
            effect_class = _CLASSIFIER.classify(tool_name)

        if turn is None:
            self._auto_turn += 1
            turn = self._auto_turn
        else:
            self._auto_turn = max(self._auto_turn, turn)

        t = tool_name.strip().lower()
        event = TraceEvent(
            index=len(self.events),
            turn=turn,
            tool_name=tool_name,
            effect_class=effect_class,
            provenance=provenance,
            inbound_flagged=inbound_flagged,
            is_memory_read=t in _MEMORY_READ_TOOLS,
            is_memory_write=effect_class is EffectClass.MEMORY_WRITE,
            summary=summary,
        )
        self.events.append(event)
        return event

    # -- profiling --------------------------------------------------------
    def profile(self) -> dict[str, int]:
        """Count of events per effect class touched in this session."""
        counts: dict[str, int] = {}
        for e in self.events:
            counts[e.effect_class.value] = counts.get(e.effect_class.value, 0) + 1
        return counts

    # -- the trajectory audit --------------------------------------------
    def audit(self) -> AuditResult:
        findings: list[AuditFinding] = []
        findings.extend(self._detect_cross_turn_exfil())
        findings.extend(self._detect_sleeper_memory())
        findings.extend(self._detect_untrusted_critical())
        findings.extend(self._detect_escalation())

        risk = AuditRisk.CLEAN
        for f in findings:
            if f.risk > risk:
                risk = f.risk

        return AuditResult(
            risk=risk,
            findings=findings,
            capability_profile=self.profile(),
            event_count=len(self.events),
        )

    # -- individual detectors --------------------------------------------
    def _detect_cross_turn_exfil(self) -> list[AuditFinding]:
        """Untrusted-influenced secret/sensitive read, then a later egress effect."""
        findings: list[AuditFinding] = []
        secret_reads = [e for e in self.events if e.effect_class is EffectClass.SECRET_READ]
        for sr in secret_reads:
            egress = [
                e for e in self.events
                if e.effect_class in _EGRESS_EFFECTS and e.turn > sr.turn
            ]
            if egress and (sr.untrusted or any(e.untrusted for e in egress)):
                first = egress[0]
                findings.append(AuditFinding(
                    pattern="cross_turn_exfil_chain",
                    risk=AuditRisk.HIGH,
                    explanation=(
                        f"secret read via '{sr.tool_name}' (turn {sr.turn}) is followed by "
                        f"a {first.effect_class.value} effect '{first.tool_name}' (turn {first.turn}) "
                        f"under untrusted influence — a data-exfiltration chain realized across turns"
                    ),
                    event_indices=[sr.index, first.index],
                ))
        return findings

    def _detect_sleeper_memory(self) -> list[AuditFinding]:
        """Injection-flagged memory write, then a later dangerous effect after a memory read."""
        findings: list[AuditFinding] = []
        flagged_writes = [
            e for e in self.events if e.is_memory_write and (e.inbound_flagged or e.untrusted)
        ]
        if not flagged_writes:
            return findings
        for fw in flagged_writes:
            later_reads = [e for e in self.events if e.is_memory_read and e.turn > fw.turn]
            for rd in later_reads:
                dangerous = [
                    e for e in self.events
                    if e.effect_class in _DANGEROUS_EFFECTS and e.turn >= rd.turn
                ]
                if dangerous:
                    dz = dangerous[0]
                    risk = AuditRisk.HIGH if fw.inbound_flagged else AuditRisk.MEDIUM
                    findings.append(AuditFinding(
                        pattern="sleeper_memory_poisoning",
                        risk=risk,
                        explanation=(
                            f"memory written under untrusted influence on turn {fw.turn}"
                            + (" (flagged as injection-shaped)" if fw.inbound_flagged else "")
                            + f" is recalled on turn {rd.turn} and precedes a "
                            f"{dz.effect_class.value} effect '{dz.tool_name}' (turn {dz.turn}) — "
                            f"a delayed/sleeper memory-poisoning pattern"
                        ),
                        event_indices=[fw.index, rd.index, dz.index],
                    ))
                    break  # one finding per poisoned write is enough
        return findings

    def _detect_untrusted_critical(self) -> list[AuditFinding]:
        """Any single untrusted-influenced critical effect (shell/code-eval/secret-read)."""
        findings: list[AuditFinding] = []
        for e in self.events:
            if e.untrusted and e.effect_class in (
                EffectClass.SHELL, EffectClass.CODE_EVAL, EffectClass.SECRET_READ
            ):
                findings.append(AuditFinding(
                    pattern="untrusted_into_critical_effect",
                    risk=AuditRisk.HIGH,
                    explanation=(
                        f"untrusted-influenced input reached a {e.effect_class.value} effect "
                        f"'{e.tool_name}' (turn {e.turn}) — should not commit under attacker influence"
                    ),
                    event_indices=[e.index],
                ))
        return findings

    def _detect_escalation(self) -> list[AuditFinding]:
        """Untrusted taint active while effect severity climbs across turns (lateral movement)."""
        untrusted_events = [e for e in self.events if e.untrusted]
        if len(untrusted_events) < 3:
            return []
        severities = [e.effect_class.severity for e in untrusted_events]
        # strictly non-decreasing and actually rising from low to consequential
        rising = all(b >= a for a, b in zip(severities, severities[1:]))
        if rising and severities[0] <= 1 and severities[-1] >= 4:
            return [AuditFinding(
                pattern="escalating_trajectory",
                risk=AuditRisk.MEDIUM,
                explanation=(
                    "under sustained untrusted influence, effect severity climbs monotonically "
                    f"from {EffectClass.READ.value} to a severity-{severities[-1]} effect across "
                    f"{len(untrusted_events)} calls — consistent with progressive lateral movement"
                ),
                event_indices=[e.index for e in untrusted_events],
            )]
        return []

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "events": [e.to_dict() for e in self.events],
            "audit": self.audit().to_dict(),
        }
