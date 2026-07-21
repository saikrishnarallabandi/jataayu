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

import asyncio
import copy
import logging
import uuid
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


def require_sink(sink, where: str, key: str):
    """Reject a non-callable sink where it is installed, rather than where it is called.

    emit_decision() swallows everything a sink raises, so telemetry can never change a
    verdict. That is deliberate, but it means a non-callable sink costs every record and
    reports itself only as a logged traceback per decision — never at the line that set
    it. None stays valid: it clears the module-level sink, and on an instance it means
    "defer to the module-level one".
    """
    if sink is not None and not callable(sink):
        raise ValueError(
            f"{where}: {key} must be callable or None, got {type(sink).__name__} {sink!r}"
        )
    return sink


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
    from jataayu.config.policy import require_bool

    global _sink, _capture_content
    # Both arguments are checked before either global moves, so a rejected call leaves
    # the previously installed sink intact rather than half-replacing it.
    # A truthy non-bool ("false") here would switch content capture on process-wide for
    # every guard, which is the opposite of what was written.
    require_bool(capture_content, "set_decision_sink", "capture_content=")
    require_sink(sink, "set_decision_sink", "sink=")
    _sink = sink
    _capture_content = capture_content


def capture_content_enabled(override: Optional[bool] = None) -> bool:
    """Resolve capture_content: per-instance override, else the module-level setting."""
    return _capture_content if override is None else override


# Depth cap for the per-leaf fallback below. deepcopy handles cycles; the manual walk
# that runs after it fails does not, so a cyclic record containing a lock would recurse
# forever. Decision records are flat-ish; 20 is far past anything real.
_MAX_SNAPSHOT_DEPTH = 20


def _repr_or_placeholder(value) -> str:
    """A __repr__ that itself raises must not cost the record."""
    try:
        return repr(value)
    except Exception:
        return f"<unreprable {type(value).__name__}>"


def _safe_copy(value, depth: int = 0):
    """Deep-copy `value`, degrading to repr PER LEAF rather than wholesale.

    Applying the fallback to a whole top-level value would turn `params` into a str
    the moment one leaf is a lock, so a structured sink (JSON schema, DB column) gets
    an object for every call but a string for that one. The structure has to survive.
    """
    try:
        return copy.deepcopy(value)
    except Exception:
        pass
    if depth >= _MAX_SNAPSHOT_DEPTH:
        return _repr_or_placeholder(value)
    if isinstance(value, dict):
        try:
            items = [(_safe_copy(k, depth + 1), _safe_copy(v, depth + 1)) for k, v in value.items()]
            copied = dict(items)
            # Two distinct keys can degrade to the SAME repr, and dict() would then drop
            # one entry from the audit record with nothing to say it happened. Keeping
            # the whole dict as text loses the structure but never loses an entry.
            if len(copied) != len(items):
                return _repr_or_placeholder(value)
            return copied
        except Exception:
            return _repr_or_placeholder(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            # type(...) preserves tuple/set; a subclass with a different signature
            # (namedtuple) raises and falls through to repr.
            orig_len = len(value)
            copied = type(value)(_safe_copy(v, depth + 1) for v in value)
            # For sets and frozensets two distinct elements can degrade to the same
            # repr string, causing the reconstructed set to be smaller than the
            # original — an entry is silently dropped, the same failure mode that
            # the dict path guards against with its len() check.
            if isinstance(copied, (set, frozenset)) and len(copied) != orig_len:
                return _repr_or_placeholder(value)
            return copied
        except Exception:
            return _repr_or_placeholder(value)
    return _repr_or_placeholder(value)


def _snapshot(record: dict) -> dict:
    """Deep-copy a decision record so a sink cannot reach caller-visible state.

    The record shares objects with the live decision (the violations list) and, under
    capture_content, with the caller's own params dict. A sink that redacts or normalizes
    in place would otherwise rewrite the very values that were classified. Values that
    refuse to deepcopy (handles, locks) degrade to their repr rather than dropping the
    record — telemetry still fires, and still hands out nothing the caller owns.
    """
    return {k: _safe_copy(v) for k, v in record.items()}


def resolve_sink(sink: Optional[DecisionSink] = None) -> Optional[DecisionSink]:
    """The sink a record would go to: per-instance wins, module-level is the fallback.

    Read at call time, never cached: set_decision_sink() is process-wide and may be called
    long after a guard was constructed. Callers use this to skip BUILDING a record nobody
    will receive; emit_decision() applies the same resolution, so a caller that resolves
    first and passes the result gets the identical target.
    """
    return sink if sink is not None else _sink


def emit_decision(record: dict, sink: Optional[DecisionSink] = None) -> None:
    """Deliver a COPY of `record` to `sink` (per-instance) or the module-level sink.

    Never raises, except for KeyboardInterrupt and asyncio.CancelledError. A broken
    telemetry callback must never be why a `deny` fails to reach the caller, so
    BaseException is swallowed and logged — SystemExit and library timeout types included.

    Those two are re-raised because neither is the sink failing: they are control flow
    aimed at the surrounding process/task. Eating KeyboardInterrupt makes Ctrl-C
    unreliable in any loop that authorizes actions; eating CancelledError makes a
    cancelled task refuse to unwind, and the event loop then sees a task that ignored
    its cancellation. A sink that raises CancelledError spuriously is indistinguishable
    from a genuinely cancelled one, and the safe reading of "cancelled" is to unwind.
    """
    target = resolve_sink(sink)
    if target is None:
        return
    try:
        target(_snapshot(record))
    except (KeyboardInterrupt, asyncio.CancelledError):
        raise
    except BaseException:
        logging.getLogger("jataayu").exception("decision sink raised; record dropped")


from jataayu.guards.effect_boundary import EffectBoundary, EffectClass, Provenance  # noqa: E402

# Fallback classifier for traces built without a boundary (its vault stays empty — we only
# use classify()). It knows no configured tool_effects, so a trace that must agree with the
# boundary that actually decided the calls should be given that boundary.
_CLASSIFIER = EffectBoundary()

# Memory-read tool names (the recall side; the write side lives in effect_boundary).
_MEMORY_READ_TOOLS = frozenset(
    {
        "memory_read",
        "recall",
        "load_memory",
        "get_memory",
        "kv_get",
        "search_memory",
        "memory.read",
        "memory.get",
        "memory.search",
    }
)

# Effects that terminate a kill chain — where exfiltrated/poisoned data does harm.
_DANGEROUS_EFFECTS = frozenset(
    {
        EffectClass.SHELL,
        EffectClass.CODE_EVAL,
        EffectClass.NETWORK,
        EffectClass.FILE_WRITE,
    }
)
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
    inbound_flagged: bool = False  # was this call's input / the tool return flagged by a guard?
    is_memory_read: bool = False
    is_memory_write: bool = False
    summary: str = ""
    # TokenFlow borrow (Ep21): flow lineage for sleeper detection
    flow_id: str = ""
    source_flow_ids: list[str] = field(default_factory=list)
    token_flow_audit: Optional[dict] = None

    @property
    def untrusted(self) -> bool:
        return self.provenance is Provenance.UNTRUSTED

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "turn": self.turn,
            "tool_name": self.tool_name,
            "effect_class": self.effect_class.value,
            "provenance": self.provenance.value,
            "inbound_flagged": self.inbound_flagged,
            "is_memory_read": self.is_memory_read,
            "is_memory_write": self.is_memory_write,
            "summary": self.summary,
            "flow_id": self.flow_id,
            "source_flow_ids": self.source_flow_ids,
            "token_flow_audit": self.token_flow_audit,
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
            "pattern": self.pattern,
            "risk": self.risk.value,
            "explanation": self.explanation,
            "event_indices": self.event_indices,
        }


@dataclass
class AuditResult:
    risk: AuditRisk
    findings: list[AuditFinding]
    capability_profile: dict[str, int]  # effect_class value -> count
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

    def __init__(self, session_id: str = "session", *, boundary: Optional[EffectBoundary] = None):
        """`boundary` supplies the effect classifier. Pass the EffectBoundary that actually
        authorizes this session's calls, or the audit will classify a tool differently from
        the guard that decided it whenever `tool_effects` is configured."""
        self.session_id = session_id
        self.events: list[TraceEvent] = []
        self._auto_turn = 0
        self._boundary = boundary if boundary is not None else _CLASSIFIER

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
        flow_id: str = "",
        source_flow_ids: Optional[list[str]] = None,
        token_flow_audit: Optional[dict] = None,
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
            effect_class = self._boundary.classify(tool_name)

        if turn is None:
            self._auto_turn += 1
            turn = self._auto_turn
        else:
            self._auto_turn = max(self._auto_turn, turn)

        t = tool_name.strip().lower()
        resolved_flow_id = flow_id or uuid.uuid4().hex[:12]
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
            flow_id=resolved_flow_id,
            source_flow_ids=source_flow_ids or [],
            token_flow_audit=token_flow_audit,
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
        findings.extend(self._detect_sleeper_memory_flow_lineage())
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
                e for e in self.events if e.effect_class in _EGRESS_EFFECTS and e.turn > sr.turn
            ]
            if egress and (sr.untrusted or any(e.untrusted for e in egress)):
                first = egress[0]
                findings.append(
                    AuditFinding(
                        pattern="cross_turn_exfil_chain",
                        risk=AuditRisk.HIGH,
                        explanation=(
                            f"secret read via '{sr.tool_name}' (turn {sr.turn}) is followed by "
                            f"a {first.effect_class.value} effect '{first.tool_name}' (turn {first.turn}) "
                            f"under untrusted influence — a data-exfiltration chain realized across turns"
                        ),
                        event_indices=[sr.index, first.index],
                    )
                )
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
                    e
                    for e in self.events
                    if e.effect_class in _DANGEROUS_EFFECTS and e.turn >= rd.turn
                ]
                if dangerous:
                    dz = dangerous[0]
                    risk = AuditRisk.HIGH if fw.inbound_flagged else AuditRisk.MEDIUM
                    findings.append(
                        AuditFinding(
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
                        )
                    )
                    break  # one finding per poisoned write is enough
        return findings

    def _detect_sleeper_memory_flow_lineage(self) -> list[AuditFinding]:
        """TokenFlow lineage upgrade: memory write flow_id -> later read -> dangerous effect via source_flow_ids."""
        findings: list[AuditFinding] = []
        for e in self.events:
            if not (e.is_memory_write and e.source_flow_ids and (e.untrusted or e.inbound_flagged)):
                continue
            for later in self.events:
                if later.turn > e.turn and e.flow_id in later.source_flow_ids:
                    if later.effect_class in _DANGEROUS_EFFECTS:
                        findings.append(
                            AuditFinding(
                                pattern="sleeper_memory_flow_lineage",
                                risk=AuditRisk.HIGH,
                                explanation=(
                                    f"memory write flow {e.flow_id} (turn {e.turn}, {e.tool_name}) with lineage {e.source_flow_ids} "
                                    f"is tainted and recalled as flow {later.flow_id} {later.tool_name} (turn {later.turn}) "
                                    f"leading to {later.effect_class.value} effect — causal flow lineage across turns"
                                ),
                                event_indices=[e.index, later.index],
                            )
                        )
        return findings

    def _detect_untrusted_critical(self) -> list[AuditFinding]:
        """Any single untrusted-influenced critical effect (shell/code-eval/secret-read)."""
        findings: list[AuditFinding] = []
        for e in self.events:
            if e.untrusted and e.effect_class in (
                EffectClass.SHELL,
                EffectClass.CODE_EVAL,
                EffectClass.SECRET_READ,
            ):
                findings.append(
                    AuditFinding(
                        pattern="untrusted_into_critical_effect",
                        risk=AuditRisk.HIGH,
                        explanation=(
                            f"untrusted-influenced input reached a {e.effect_class.value} effect "
                            f"'{e.tool_name}' (turn {e.turn}) — should not commit under attacker influence"
                        ),
                        event_indices=[e.index],
                    )
                )
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
            return [
                AuditFinding(
                    pattern="escalating_trajectory",
                    risk=AuditRisk.MEDIUM,
                    explanation=(
                        "under sustained untrusted influence, effect severity climbs monotonically "
                        f"from {EffectClass.READ.value} to a severity-{severities[-1]} effect across "
                        f"{len(untrusted_events)} calls — consistent with progressive lateral movement"
                    ),
                    event_indices=[e.index for e in untrusted_events],
                )
            ]
        return []

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "events": [e.to_dict() for e in self.events],
            "audit": self.audit().to_dict(),
        }
