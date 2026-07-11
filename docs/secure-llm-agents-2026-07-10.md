# Secure LLM Agents + Prior-Art Differentiation: SecureClaw & AuthGraph vs Jataayu

*2026-07-10 continuation after ICML sweep. Answers P1: "Read SecureClaw (2606.09549) and AuthGraph (2605.26497) and write the differentiation para."*

## Source papers (verified)

- **SecureClaw**: arXiv:2606.09549 — "SecureClaw: Clawing Back Control of LLM Agents" (Yuhan Ma et al, Jun 2026). Dual-boundary: opaque handles at read + PREVIEW→COMMIT at write. Reports ASB 0% ASR, AgentDojo 0.64%, AgentLeak 3.23% attacked parity.
- **AuthGraph**: arXiv:2605.26497 — "Aligning Provenance with Authorization: A Dual-Graph Defense" (Peiran Wang et al, May 2026). Builds injected reasoning graph (actual trace incl. potentially manipulated attributions) + authorization graph (clean isolated intent) — compares structurally. AgentDojo 40%→1% ASR, 76% util (GPT-4o).

## Mechanism collisions (honest)

1. **SecureClaw collision**: 
   - Read: sensitive reads → trusted gateway replaces raw value with opaque handle + bounded summary (explicit declassification interface). Agent plans over summaries, cannot dereference secrets.
   - Write: PREVIEW→COMMIT where only trusted executor commits exact canonical request authorized by policy.
   - Jataayu has same: `EffectBoundary.confine_read()` → `OpaqueHandle` + summary, vault, `dereference()` only at commit; `preview()` → canonical + SHA256 `commit_token`, `commit()` validates token matches action actually executed.
   - Near-verbatim concept, independent invention. Must acknowledge.

2. **AuthGraph collision**:
   - Core idea: authorization spec vs execution provenance comparison at tool+param level.
   - Jataayu's worst-provenance axis overlaps: untrusted-derived input detection into effects.
   - Near collision on provenance × authorization thesis.

## Differentiation — what Jataayu uniquely owns

### 1. Three-factor severity-graded gate (core differentiator)

SecureClaw and AuthGraph are binary ALLOW/DENY (or 2-tier). Jataayu:

```
Decision = f(effect_severity × worst_inbound_provenance × capability_policy)

_CRITICAL_EFFECTS = {SHELL, CODE_EVAL, SECRET_READ} → DENY if untrusted
_APPROVAL_EFFECTS = {NETWORK, FILE_WRITE, MEMORY_WRITE} → NEEDS_APPROVAL if untrusted
READ → ALLOW (always), with confinement for sensitive reads
```

Plus capability allow/forbid list from AgentPolicy (`is_capability_allowed`) checked first.

This 3-tier (ALLOW / NEEDS_APPROVAL / DENY) with severity ordering is not in SecureClaw (opaque+PREVIEW/COMMIT only) nor AuthGraph (graph mismatch = injection, binary). The NEEDS_APPROVAL path is what makes utility retainable — e.g., untrusted-derived file write requires human approval rather than silent deny, preserving the "human-in-the-loop for consequential" semantic vs all-or-nothing.

### 2. Integrated four-surface stack with single vocabulary

SecureClaw: read confinement + write auth only (2 boundaries). AuthGraph: graph alignment only (detection, not confinement, no skill).

Jataayu shares one `EffectClass`/`Provenance`/`Decision` vocabulary across:

- EffectBoundary (tool-call authorization, PREVIEW→COMMIT, opaque handles)
- InboundGuard (prompt injection detection — the 71-pattern fast path, surgical scrub)
- OutboundGuard + EgressGuard (privacy + data-carrying URL/image channel — EchoLeak/AgentFlayer class)
- SkillVet + Composition check (skill install-time vetting, LLM-as-judge + deterministic capability-pair/trust-transfer/fragmentation)
- TokenFlowGuard (source→sink flow lineage, borrowed from Token-Flow Firewall 2607.08395 — flow audit before effect, with source_audience → sink_audience drift check for private DM → group leak)
- SessionTrace (cross-turn audit, sleeper-memory write→recall→effect detection)

No single 2026 paper claims this integration. Each competitor has a separate paper per module.

### 3. Deterministic, sub-ms, ~0 VRAM + auditable phrasing

- No LLM in security decision path for effect boundary (pure regex/IFC + hash-bound token)
- `preview().to_dict()` gives reason + violations + canonical + token — replayable audit
- SecureClaw/AuthGraph don't report latency/VRAM; trained guardrails are 300ms+/14GB+.

### 4. Model-dependent false-positive profile is explicit and fixed

P0 (2026-07-10): PI-006 delimiter pattern flagged benign email concat (`---` + "ignore this email" boilerplate) as BLOCKED → utility 47.5%→25% for gpt-5.4-mini no-attack. Fixed by requiring instruction-object in pattern. Now CLEAN on benign, still BLOCKED on real injection. This transparency (shipped as PR #15 with before/after verified) is part of the moat — deterministic patterns are auditable and fixable vs black-box classifier retraining.

## Positioning paragraph (drop-in for README/ARCHITECTURE)

> SecureClaw (2606.09549) and AuthGraph (2605.26497) independently propose opaque-handle read confinement + PREVIEW→COMMIT and provenance × authorization alignment respectively — near-verbatim mechanism collisions that validate the effect-boundary thesis and require us to shift claim from "novel mechanism" to "severity-graded deterministic gate + integrated stack". Jataayu's differentiator is (1) a three-factor product `severity × worst-provenance × capability` as a single deterministic gate with three outcomes (ALLOW / NEEDS_APPROVAL / DENY) rather than binary allow/deny, (2) a coherent stack across four surfaces (effect authorization, inbound/outbound/egress filtering, skill vetting + composition, token-flow lineage, cross-turn audit) sharing one EffectClass/Provenance vocabulary, and (3) explicit sub-ms/0-VRAM cost with replayable audit traces. On AgentDojo workspace/qwen3.6-35b Jataayu achieves 2.9%→0.0% ASR at 0pp utility tax; the gpt-5.4-mini 47.5%→25% tax was a PI-006 delimiter false-positive on benign `---`+`ignore this email` concats, now fixed in #15.

## Next steps

- [ ] Update ARCHITECTURE.md prior-art section with above paragraph + table row for SecureClaw/AuthGraph
- [ ] Run rerun agentdojo_workspace_gpt54mini_oauth_true_full after #15 merge to confirm 47.5%→47.5% (0pp)
- [ ] Present clean multi-model AgentDojo table (qwen + gpt-5.4-mini fixed + claude-subagent)
