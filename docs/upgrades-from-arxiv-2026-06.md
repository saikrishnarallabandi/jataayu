# Jataayu — upgrade notes from the 2026 agent-security literature

*Author: research pass, 2026-06-23. Source: six June-2026 arXiv papers on agent/skill
security (pulled from the Sangraha arXiv feeds) plus the WorldShift explainer reel built
from them. These are notes + a proposed roadmap, not committed work.*

> **Companion video** (1:49, the same six papers, plain-language):
> `project_worldshift/data/social_cache/six-papers-on-breaking-and-defending-ai-agents-soc-clawsec-arxiv.mp4`
> Thesis of the reel — and of these notes:
> **"You can't secure an agent by checking its final answer. You have to watch what it
> touches. Execution is the new attack surface."**

---

## TL;DR

Jataayu today is a **boundary text-filter with taint→sink flow**: it checks inbound
*content* (`guards/inbound.py`), scrubs outbound *content* (`guards/outbound.py`), and
blocks tainted-data→dangerous-sink via `core/taint.py` + `integrations/mcp_gateway.py`.
That is genuinely ahead of most tools (the outbound privacy guard especially).

The 2026 literature says the frontier has moved past text at the boundary to three places
Jataayu does **not** yet cover:

1. **Skills** — community/agent skills are an unvetted attack surface (install-time).
2. **Execution context** — memory writes, tool *returns*, and runtime traces, not just the
   user prompt and the final reply.
3. **Composition** — individually-safe skills combine into unsafe capability sets.

None of these require throwing away Jataayu's design. They extend the surface model and
reuse the LLM slow-path as a judge. **Recommendation: yes, upgrade — start with skill
vetting and the two new execution surfaces (both low-lift, high-leverage), then the
compositional and dual-boundary work.**

---

## Where Jataayu already aligns (keep / lead with these)

| Strength | Module | Why it matters in the 2026 framing |
|---|---|---|
| Taint tracking, data→sink | `core/taint.py` | The execution-centric idea in embryo: track what tainted input *reaches*. |
| `before_tool_call` hook | `integrations/mcp_gateway.py` | The natural insertion point for effect-sink authorization (SecureClaw) and trace audit (RSA). |
| Surface-aware trust | `surfaces/profiles.py` | The right abstraction to add `tool-return` / `memory-*` / `skill-metadata` surfaces. |
| LLM slow-path judge | `core/engine.py`, `guards/*` | Already an LLM-as-judge — exactly what SkillVetBench needs for instruction-layer risk. |
| Outbound privacy guard | `guards/outbound.py` | Rare; a head start on SecureClaw's read-boundary confinement (see P5). |

---

## Per-paper gap → concrete upgrade

### 1. SkillVetBench — vet skills, don't just filter content  · arXiv:2606.15899
**Finding:** community skills are unvetted; static/code scanners miss **89–100%** of
instruction-layer threats (prompt injection, memory poisoning). An LLM-as-Judge with a
multi-dimension risk score (SARS) caught 78/78 malicious skills with zero false negatives.

**Gap in Jataayu:** it guards *runtime content*; it has no notion of vetting a *skill* at
install time. (`skills/` today only holds `openclaw/SKILL.md`, i.e. Jataayu-as-a-skill — not
a vetting target.)

**Upgrade (P0):** add `guards/skill_vet.py` + `jataayu vet-skill <path>` CLI.
- Input: a skill's NL instructions (SKILL.md), code, and tool/MCP definitions.
- LLM-judge scores a Jataayu Skill-Risk vector: `instruction_hijack`, `data_exfil`,
  `memory_poisoning`, `capability_escalation`, `unexpected_side_effects`, each with a short
  rationale; roll up to SAFE/REVIEW/MALICIOUS.
- Reuse the existing slow-path backend selection; ship a pattern pre-filter for the obvious
  cases (encoded payloads, exfil URLs) so cheap cases never hit the LLM.

### 2. Runtime Skill Audit (RSA) — trace evidence beats static patterns · arXiv:2606.11671
**Finding:** a skill can look benign statically and turn harmful only when invoked. Static
detectors **collapse after 1–2 rounds** of self-evolving attacks; runtime trace auditing
held at ~90% accuracy / 88% TPR.

**Gap in Jataayu:** the fast path is static regex (brittle exactly where the paper says it
breaks), and `before_tool_call` decisions are per-call — no accumulated behavioral profile.

**Upgrade (P2):** add `core/audit.py` with a `SessionTrace` that `mcp_gateway` appends every
tool call to; profile risk-relevant interfaces (fs / net / exec / memory) per skill and label
from trace evidence. `jataayu audit <session>` summarizes. This turns the existing hook from a
point check into a behavioral auditor and hardens us against self-evolving payloads.

### 3. When Safe Skills Collide — compositional / capability-isolation checks · arXiv:2606.00448
**Finding:** individually-safe skills compose into unsafe sets; per-skill scanning misses
**~14K** genuine risk memberships in one registry *by construction*. Realization is gated by
the host model's disposition. Fix: install-time compositional checks + capability isolation.

**Gap in Jataayu:** every check is single-item, in isolation. No cross-skill reasoning.

**Upgrade (P1):** `jataayu_check_skillset(installed_skills) -> CompositionRisk`.
- Tag each skill with capabilities (from the P0 vetting pass): `reads_secrets`,
  `network_write`, `exec`, `fs_write`, `memory_write`, …
- Flag dangerous *pairs/chains*: `reads_secrets + network_write` (exfil), `fs_write + exec`
  (dropper), `memory_write + <any-instruction-following skill>` (poisoning vector).
- Wire capability allowlists into `config/policy.py` (per-agent capability isolation), so a
  composition that unlocks a forbidden capability is blocked at install, not at runtime.

### 4. SafeClawBench — measure harm in stages, not just text · arXiv:2606.18356
**Finding:** separating *semantic acceptance* vs *audit-evidence* vs *sandbox-observed* harm
matters: **291 of 347** real sandbox harms occurred in cases that **passed the semantic
check**. Text-level grading badly undercounts real harm.

**Gap in Jataayu:** outbound `BLOCK` and inbound scoring are semantic/text-level; there is no
"did an actual effect occur" signal, and our own tests grade on text outcomes.

**Upgrade (P2):**
- Adopt the three staged endpoints in Jataayu's **own** test suite / metrics
  (`tests/`): semantic-accept, audit-evidence, sandbox-effect — so we stop reporting a
  text-pass as a win when an effect still fired.
- Add an effect-observation layer in `core/audit.py`: after `before_tool_call`, record audit
  evidence (+ optional sandbox state-delta) so Jataayu can report harm at the *effect* level.

### 5. SecureClaw — dual-boundary: confine reads, authorize effects · arXiv:2606.09549
**Finding:** a two-wall architecture hit **0% ASR on ASB** while keeping utility — (a) secrets
swapped for **opaque handles** at the *read* boundary (the runtime plans over references, never
dereferences plaintext), and (b) external writes follow **PREVIEW→COMMIT**, where only a trusted
executor commits the exact policy-authorized canonical request.

**Gap in Jataayu:** we confine plaintext only at the *out* boundary (outbound redaction) — i.e.
secrets enter the runtime as plaintext and we scrub on the way out, which is leaky. And
`before_tool_call` gates on taint, not a two-phase authorization bound to a canonical request.

**Upgrade (P2, biggest architectural lift, highest ceiling):**
- **Read-boundary confinement:** a secret-vault wrapper that replaces secrets with opaque
  handles *before* they reach the agent, with bounded declassification. This is the dual of
  today's outbound guard — turn "scrub on exit" into "never admit plaintext."
- **Effect-sink PREVIEW→COMMIT:** extend `mcp_gateway` from block/allow to a two-phase commit —
  the agent previews a canonical action; a trusted executor commits only the exact authorized
  request. Composes cleanly with the existing taint check.

### 6. Red-Teaming Agent Execution Contexts (DeepTrap) — the context is the attack surface · arXiv:2605.11047
**Finding:** adversaries compromise the *mutable execution context* — files, **memory**, tools,
skills — not just the prompt, and the agent still finishes the user task perfectly (so
**final-response evaluation is insufficient**). They call for execution-centric, trajectory-level
evaluation.

**Gap in Jataayu:** inbound checks cover external *content* and MCP tool *descriptions*, but not
tool **returns** or persistent **memory** reads/writes — the exact channels DeepTrap and
SafeClawBench exploit (tool-return injection, memory poisoning/extraction).

**Upgrade (P0, with #1):** add surfaces to `surfaces/profiles.py` and route them through
`guards/inbound.py`:
- `tool-return` — run inbound checks on **tool outputs** before the agent consumes them.
- `memory-write` / `memory-read` — check anything written to / read from persistent memory
  (poisoning + extraction).
- `skill-metadata` — check skill/tool manifests at load (feeds #1).
Then evaluate trajectory-level, not just final reply.

---

## Proposed roadmap (by leverage / lift)

**P0 — reuse what we have, close the biggest live gaps**
- [x] `tool-return`, `memory-read/write` surfaces (DeepTrap, SafeClawBench) — shipped on
  `feat/execution-surfaces`: surface profiles + inbound multipliers, `after_tool_call` /
  `inspect_tool_response` return-value scanning in `mcp_gateway`, and
  `jataayu_check_tool_return` / `_memory_write` / `_memory_read` convenience API. 25 tests.
- [x] `guards/skill_vet.py` + `jataayu vet-skill` LLM-judge with a Skill-Risk vector (SkillVetBench)
  — shipped: `SkillVetGuard` (pattern pre-filter → LLM-as-Judge), the `skill-metadata`
  surface, `jataayu vet-skill <path>` CLI, and `jataayu_vet_skill()` API. Scores the 5-dim
  Skill-Risk vector → SAFE/REVIEW/MALICIOUS, and tags **capabilities** (exec, reads_secrets,
  network_write, …) which feed P1 composition. Positioned as a complement to OpenClaw's static
  scanner: it reasons about the *instruction layer* (markdown prose), where command patterns are
  treated as soft (could be documentation) vs. code/manifests where they hard-block. 14 tests.

**P1 — composition & policy**
- [x] `jataayu_check_skillset()` capability tags + dangerous-pair/chain detection (SkillReact)
  — shipped `guards/composition.py`: `check_skillset()` / `jataayu_check_skillset()` /
  `jataayu vet-skillset` CLI. Flags dangerous capability combos realized **across** skills
  (exfil, dropper, download-run, memory-poison vector) and names which skill contributes each
  capability; skips intra-skill combos (P0's job). Accepts paths, dicts, or `SkillVetResult`s.
- [x] capability allowlists in `config/policy.py` (capability isolation) — `AgentPolicy`
  gained `allowed_capabilities` / `forbidden_capabilities` + `is_capability_allowed()` /
  `capability_violations()`. A composition that unlocks a forbidden capability is blocked at
  **install** (verdict MALICIOUS), not discovered at runtime. 18 tests.

**P2 — execution-centric core (bigger lifts)**
- [ ] `core/audit.py` `SessionTrace` + `jataayu audit` runtime behavioral auditing (RSA)
- [ ] effect-sink **PREVIEW→COMMIT** in `mcp_gateway` + opaque-handle read-boundary vault (SecureClaw)
- [ ] staged harm metrics (semantic / audit / sandbox) in `tests/` (SafeClawBench)

**Framing for the README/positioning:** Jataayu started as inbound-injection + outbound-privacy.
The 2026 work says the next chapter is **skill-aware + execution-aware**: vet skills before they
load, watch what they *touch* at runtime, and reason about what they unlock *together*. That is a
natural extension of the eagle's instinct the project is named for — see the threat in the
context, judge it, and act — not just pattern-match the words.

## Sources
- Runtime Skill Audit — https://arxiv.org/abs/2606.11671
- SkillVetBench — https://arxiv.org/abs/2606.15899
- When Safe Skills Collide — https://arxiv.org/abs/2606.00448
- SafeClawBench — https://arxiv.org/abs/2606.18356
- Red-Teaming Agent Execution Contexts (DeepTrap) — https://arxiv.org/abs/2605.11047
- SecureClaw — https://arxiv.org/abs/2606.09549
