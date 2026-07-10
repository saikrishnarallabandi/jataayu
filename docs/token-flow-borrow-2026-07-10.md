# Borrow from Token-Flow Firewall for Jataayu — Ep21 Spec

**Date:** 2026-07-10
**Source papers:** 
- Token-Flow Firewall (TokenWall) arXiv:2607.08395 — Episode 21 https://open.spotify.com/episode/4Ylb9KOjZ68rBRSMtG1JbC
- Multi-Agent Firewall arXiv:2607.08282 — Episode 22 https://open.spotify.com/episode/7EWKZjVPGBtsIL35djdjdX

**Why this maps:** Jataayu already does provenance x effect severity at tool-commit time (EffectBoundary) + cross-turn trajectory audit (SessionTrace). TokenWall formalizes the earlier point in pipeline: intercept *token flows* before they become tool args.

## What TokenWall adds conceptually

1. **Flow, not just call:** Security-critical interactions travel as natural-language token flows: memory updates, tool arguments, retrieved file contents, inter-component messages, skill definitions. Unsafe content can survive via persistent state.

2. **Source -> Sink audit records:** Not just provenance label, but structured record: source (where text came from, source type, trust), sink (where it's headed, privilege), semantic risk, context.

3. **Boundary-aware escalation:** Local fast inspection for clearly safe/unsafe, selective escalation to stronger arbitration model *with full provenance* only when ambiguous + high-risk + privileged sink.

4. **Memory as sink + Skills as persistence amplifier:** Writing durable memory or creating reusable skill = privileged sink, not cache. Web scrape -> memory -> skill -> later auto-execution is semantic supply-chain.

## What we can borrow — concrete

### 1. New module: `jataayu/guards/token_flow.py` (FlowGuard)

Current: `Value(data, Provenance.UNTRUSTED, source="web-page")` flows into `EffectBoundary.preview()`.

New: Intercept at flow-creation time, before preview.

```python
@dataclass
class TokenFlow:
    flow_id: str
    source_type: str  # "web-page", "tool-return", "memory-recall", "dm", "group-chat", "file-read"
    source_provenance: Provenance
    source_surface: str  # maps to profiles.py: "github-issue", "whatsapp-group", "direct-message", "memory"
    content_preview: str  # first 300 chars, never raw secret
    content_hash: str
    sink_type: str  # "file_write", "memory_write", "skill_write", "network", "outbound", "shell"
    sink_surface: str
    sink_privilege: int  # severity
    turn: int
    session_id: str
    semantic_score: float = 0.0 # from fast path
    audit_record: dict = ...

class TokenFlowGuard:
    def audit_flow(self, flow: TokenFlow) -> FlowDecision: ...
```

**Location:** `jataayu/guards/token_flow.py`, reuses `core/taint.py` sourcing, `surfaces/profiles.py` for surface -> trust.

### 2. Structured audit records (upgrade SessionTrace)

Today SessionTrace stores TraceEvent with effect_class + provenance + inbound_flagged.

Borrowed upgrade: store full TokenFlow audit record chainable across turns.

```python
# In SessionTrace.record():
# Before: TraceEvent(tool_name, effect_class, provenance)
# After: also attach source_flow_ids: list[flow_id] that contributed to this tool call
# This lets us answer: this file_write came from memory that came from web-page 5 turns ago
```

This directly enables stronger sleeper-memory detection: instead of "memory write flagged + later dangerous effect", we track the actual flow ID lineage.

### 3. Memory as privileged sink — raise severity / add policy

Today `_APPROVAL_EFFECTS` includes MEMORY_WRITE when untrusted. TokenWall argues it should be treated as privileged as NETWORK/FILE_WRITE because it amplifies persistence.

Options:
- In policy, add `memory_write` as requiring approval when provenance = UNTRUSTED (already) but also *when source_surface != sink_surface_audience* (surface integrity). E.g., DM-derived memory -> group-visible recall should be flagged.
- Add new EffectClass `SKILL_WRITE` or `AUTOMATION_WRITE` (currently skill_vet is install-time only). Token flows that write skills/automations = severity 4-5, always needs approval if untrusted-derived.

### 4. Skills as persistence amplifier — extend skill_vet

Current `skill_vet.py` vets skill at install time with LLM judge.

Borrow: On *skill creation/update* via tool (not just install), run token-flow audit: what source flows built this skill? If any flow is untrusted or cross-surface, mark skill as tainted and require re-vet.

Pseudo in `effect_boundary.py`:
```python
if effect == EffectClass.FILE_WRITE and params["path"] in skill_dirs:
    flow_audit -> escalate to SkillVetGuard
```

### 5. Boundary-aware escalation (refine fast + slow path)

Jataayu already has fast regex (55+ patterns) + slow LLM. TokenWall refines *when* to escalate:

Fast path clear cases:
- source = trusted + sink = low privilege -> ALLOW
- source = untrusted + sink = critical (shell/secret_read/code_eval) -> DENY (already deterministic)

Escalation when:
- medium semantic risk + privileged sink (file_write, network, memory_write, skill_write)
- cross-surface flow (source_surface trust != sink_surface trust) + ambiguous
- combination risk (single flow looks benign, but chain of flows from same source escalates)

Escalation payload: Send full TokenFlow audit record, not stripped snippet, to slow path LLM. Prompt includes source lineage: "This file write's argument came from memory recall turn 3 which came from web tool return turn 1 flagged as injection-shaped".

Implement in `TokenFlowGuard.audit_flow()` returning `NEEDS_LLM_ARBITRATION` with record.

### 6. Integration order (proposed pipeline)

Old pipeline (per action):
`inbound -> taint -> effect_boundary preview->commit -> outbound -> egress`

New pipeline:
`token_flow audit (source->sink record + local check) -> inbound fast/slow -> effect_boundary preview (deterministic deny still wins) -> memory_write as sink check -> outbound surface-integrity -> egress channel -> SessionTrace append TokenFlow`

TokenFlow is the fabric that connects inbound, memory, skill, and egress stages with same record type.

### 7. Eval to borrow

Create `eval/run_token_flow_bench.py` that replays two TokenWall patterns Jataayu should now block:

- **Pattern A: Sleeper via memory:** Turn1 tool returns injection-shaped payload -> agent writes to memory (should flag TokenFlow to MEMORY_WRITE sink) -> Turn5 recall -> file_write. SessionTrace should flag sleeper_memory_poisoning with flow lineage.

- **Pattern B: Skill supply-chain:** Web page content -> agent writes skill file in skills/ that auto-executes later. TokenFlow to SKILL_WRITE sink should DENY/NEEDS_APPROVAL + trigger skill_vet.

Add to existing `run_memory_poison_bench.py` and `run_composition_bench.py` as sub-cases.

## Why this still differs from TokenWall

- Jataayu keeps deterministic effect boundary as the *guarantee*. TokenFlow audit is defense-in-depth that provides context and early block, but shell/secret-read under untrusted influence is still DENY regardless of semantic score. TokenWall appears to rely more on semantic scoring.
- Jataayu's unique wedge (per recent positioning) is **surface integrity**: audience drift (DM fact -> group), memory scope confusion, durability labels. TokenWall's source/sink abstraction maps directly: source_surface + sink_surface + audience field in TokenFlow.

## Implementation steps (small slices)

**Slice 1 (1 day):** `TokenFlow` dataclass + `token_flow.py` with local inspection only (no LLM), unit tests for source->sink deny/allow matching current EffectBoundary behavior. Add to `janaayu/__init__.py` export.

**Slice 2:** Wire into `api.py`: new `jataayu_audit_flow()` that builds TokenFlow from Value+tool and calls EffectBoundary. Keep backward compat.

**Slice 3:** Extend SessionTrace to store flow_ids lineage. Update `audit.py` detectors to use flow lineage for sleeper detection.

**Slice 4:** Add SKILL_WRITE effect class, update classify() in effect_boundary to treat writes to `skills/*.md` / `automations.yaml` / `runs/` as privileged.

**Slice 5:** Add escalation prompt template in `core/engine.py` that includes full TokenFlow audit record when calling LLMBackend.

**Slice 6:** Bench + docs update.

## Links back to pods

- Ep19 (Remember When It Matters): memory as intervention -> we now treat memory write as privileged sink needing admission control.
- Ep20 (Agents Need Boundaries): boundaries as systems -> token flow is the boundary primitive.
- Ep21 (Token-Flow): flow-level interception.
- Ep22 (Multi-Agent Firewall): network-layer interception (HTTP/WS) + harness-layer interception (our TokenFlow) share same provenance model. Together: browser ext/proxy for web LLM + TokenFlow for agent harness = full stack.


## Update 2026-07-10 18:53 Slice 2-3 Applied

- `api.py`: new `jataayu_audit_flow()` that builds TokenFlow from preview params, returns dict with decision/risk/arbitration flag. No breaking change, additive.
- `core/audit.py`: TraceEvent now stores `flow_id`, `source_flow_ids`, `token_flow_audit`. `SessionTrace.record()` accepts same. New detector `_detect_sleeper_memory_flow_lineage()` that tracks memory write flow_id -> later dangerous effect via source_flow_ids chain. Wired into `audit()` alongside existing sleeper detector.
- This enables causal flow lineage: Turn1 web-fetch flow-web-001 -> memory_write flow-mem-001 lineage [flow-web-001] -> file.write flow-file-001 lineage [flow-mem-001] is now flagged as `sleeper_memory_flow_lineage` HIGH with both indices.
- Next: Slice 4 skill_write auto-detection from filesystem path + workflow file detection.

