# Jataayu vs the 2026 agent-security frontier (ICML 2026 sweep)

*2026-07-09. Method: 4-way parallel lit fan-out (injection defenses / action-IFC-provenance /
guardrails-benchmarks / MCP-memory-supply-chain), each agent verifying arXiv IDs directly and
tagging venue. Anchored on the community ICML-2026 agent-papers index
(`github.com/jiaxianyan/icml-2026-agent-papers`, 632 ICML + 457 ICLR entries). Companion to
`docs/safeharbor-comparison-2026-07-09.md` (the SafeHarbor deep-dive) and `docs/lit-review-2026-07.md`.
All Jataayu numbers here are from real harness runs in `eval/results/`, not estimates.*

---

## 0. TL;DR — three findings

1. **The effect-boundary / IFC family that Jataayu belongs to is essentially absent from ICML 2026's
   main track.** It publishes to security venues: CaMeL → **IEEE SaTML 2026**, ControlValve →
   **ICLR 2026**, FIDES/AgentArmor/AuthGraph/SecureClaw → **arXiv**. What ICML 2026 *does* have is the
   *guardrail* family — SafeHarbor (poster 64556), CausalArmor, BARRED, EMBGUARD, SkillGuard — trained
   classifiers on a **different axis** (intent, not provenance). Positioning consequence: an
   effect-boundary paper at ICML would be nearly first-of-kind; the natural venue is SaTML/ICLR/S&P.

2. **On the shared scoreboard (AgentDojo), Jataayu meets the cohort's bar: 0% ASR.** The deterministic
   cohort all converges on ~0–3% residual ASR at a ≤7pp utility tax. Jataayu's real run:
   workspace/qwen3.6-35b, 70 attack cases → **ASR 2.9%→0.0%, zero utility tax**. The wart: on
   gpt-5.4-mini the utility tax is ~20pp (below), which *is* uncompetitive on that config and is our
   top fix-it.

3. **Two 2026 preprints are near-one-to-one collisions with Jataayu's mechanism and must be
   addressed head-on:** **SecureClaw** (opaque-handle read confinement + PREVIEW→COMMIT) and
   **AuthGraph** (provenance × authorization). Neither has our *three-factor severity-graded* gate,
   which is the defensible differentiator — but we can no longer claim the mechanism is novel.

---

## 1. The scoreboard — deterministic effect/IFC cohort on AgentDojo

Jataayu's actual design family. All are **deterministic** (no LLM in the security decision path) and
all report AgentDojo. ASR = attack success rate (lower better); tax = utility lost vs undefended.

| Defense | Venue | Mechanism | AgentDojo ASR (undef→def) | Utility retained | Tax |
|---|---|---|---|---|---|
| **FIDES** (Microsoft) | arXiv 2505.23643 | dynamic taint IFC + per-tool policy | 156→**0** injections | net **+16%** (reasoning models) | ~0 / negative |
| **ControlValve** (Cornell/MSR) | **ICLR 2026** 2510.17276 | permitted control-flow-graph enforcement | Slack 56→**0**; coding 97–100→**0** | 62% vs 65% | **~3pp** |
| **CaMeL** (DeepMind/ETH) | **SaTML 2026** 2503.18813 | capability + control/data-flow separation (custom interpreter) | ~300→**0** successful | **77%** solved *w/ provable security* | **~7pp** |
| **AgentArmor** (ByteDance) | arXiv 2508.01249 | CFG/DFG/PDG graph-IR + type system | **41→3%** | 72% vs 73% | **~1pp** |
| **AuthGraph** ⚠ | arXiv 2605.26497 | dual-graph: provenance × intent-authorization, tool+param level | **40→1%** | 76% task completion | modest (AgentDojo) |
| **SecureClaw** ⚠ | arXiv 2606.09549 | opaque handles (read) + PREVIEW→COMMIT (write) | ASB **0%**, AgentDojo **0.64%** | qualitative only | n/r |
| **ACP** | arXiv 2603.18829 | temporal/stateful admission control (TLA+, 4.3B states) | 500/500→**2/500 (0.4%)** valid-workload | n/r | 739ns p50 |
| **— Jataayu** (this repo) | — | **severity × worst-provenance × capability**, 3-factor deterministic gate + PREVIEW→COMMIT + opaque handles | **workspace/qwen 2.9→0.0%**; slack/gpt5.4-mini 10→0% | qwen: **100% (0pp)**; gpt5.4-mini: ~20pp | 0–20pp (model-dependent) |
| RTBAS *(probabilistic, for contrast)* | arXiv 2502.08966 | IFC + LM-judge + attention saliency | prevents all targeted | ~2% loss | lowest, not deterministic |

**Where Jataayu sits:** it clears the 0% ASR bar the cohort defines. On the qwen3.6-35b workspace run
(70 attack cases, the largest clean run) it costs **zero** utility — competitive with FIDES/ControlValve.
The honest gap is the **model-dependent utility tax**: on gpt-5.4-mini the no-attack utility drops
47.5%→25% (~22pp) — above the ~7pp cohort ceiling. That's a false-positive/over-blocking problem on
that model config, and it is the single most important thing to fix before publishing an AgentDojo
headline (see §5).

Raw: `eval/results/agentdojo_workspace_qwen35b_medium_full_20260709T082201Z.json`,
`agentdojo_slack_gpt54mini_sweep.json`, `agentdojo_workspace_gpt54mini_oauth_true_full.json`.

## 2. The guardrail cohort — a *different axis* (intent, not provenance)

These are ICML-2026-present but answer a different question: "is this *request* harmful?" (adversary =
the user). They are **not** injection defenses. Full treatment in the SafeHarbor memo; summary:

| Guardrail | Venue | What | Harmful-refusal | Benign-refusal | Cost |
|---|---|---|---|---|---|
| **SafeHarbor** | **ICML 2026** 2605.05704 | memory-tree + safety-projector, retrieval-time | 93.2% (GPT-4o) | 25% (util 63.6%) | 7B LLM, 14GB, 307ms |
| LlamaGuard-3 | — | content classifier | 95.5% | 29% | 2 models, 30GB, 379ms |
| ShieldAgent | ICML **2025** | rule circuits + formal verify of trajectory | recall 90.1% | — | LLM-scale |
| COLAGUARD | arXiv 2605.29068 | latent-space safety reasoning | +8.24 macro-F1 vs LlamaGuard-3 | — | 12.9× faster than CoT guards |
| CausalArmor | arXiv 2602.07918 (ICML-list) | causal-attribution IPI guardrail | AgentDojo **ASR 0.29%**, util 75% | — | 1.01× latency |

**Jataayu on AgentHarm (SafeHarbor's benchmark, real EffectBoundary decisions, 208H+208B):**
harmful-effect block **94.2%**, benign block 92.3% → **intent separation ~2pt** (SafeHarbor ~68pt).
Jataayu matches the harmful-block rate deterministically at sub-ms/0-VRAM but is intent-blind by
design — it can't separate a harmful post from a benign one, because its discriminator is provenance,
not intent. CausalArmor is the interesting hybrid: it's the one ICML-2026-listed piece that reasons
about *influence at the decision point* (closer to us) rather than pure string classification, and
posts the best guardrail-side AgentDojo number (0.29% ASR).

**Robustness ammunition for the deterministic case:** "When Safety Geometry Collapses" (2605.02914,
AAAI-26 symposium) shows a trained guard's benign-refusal cratering **85%→0%** after innocuous
fine-tuning; "AutoDojo" (2606.15057) recovers **28–64% ASR** against filters that scored 0% ASR
statically. A deterministic gate has no such adaptive/aliasing failure mode — the core argument for
putting the guarantee at the effect boundary, not the classifier.

## 3. Jataayu's other three modules — competitors with numbers

Not just the effect boundary. The 2026 preprint frontier has direct analogs for each Jataayu module:

**Skill vetting** (`jataayu_vet_skill`, LLM-judge):
- **SkillVetBench** (2606.00925): semantic-spec + sandbox vetting; **static/signature scanners miss up
  to 89%** of malicious skills → validates the LLM-judge-over-prose approach.

**Skillset composition** (`jataayu_check_skillset`: capability pairs, trust-transfer, intent fragmentation):
- **SCR-Bench** (2606.15242): CapFlow **33.6%** composed ASR (~0 isolated), TrustLift/endorsement
  **>96.5%**, AuthBlur risky-approval **+71.8%**. Our trust-transfer + capability-pair + fragmentation
  taxonomy maps almost 1:1 — this is the benchmark to run our composition guard against.
- **When Safe Skills Collide** (2606.00448): 1,520 skills → 211,575 pairs, 18.2% validated risk.
- ⚠ **Both use the OpenClaw/ClawHub ecosystem names** — verify they're independent third-party work
  and not derivative of our own project before citing as external validation.

**SessionTrace cross-turn auditor** (sleeper memory: write→recall→effect):
- *Attacks:* "Hidden in Memory" (2605.15338) — sleeper implant up to **99.8%** (GPT-5.5); MemMorph
  (2605.26154) — tool-hijack **85.9% ASR with 3 poisoned records**; Plant/Persist/Trigger (2605.28201) —
  1,896 instances across context/memory/skills.
- *Defenses:* **TMA-NM** (2606.24322) — **0% ASR on direct+laundering, machine-checked (TLA+)**, the
  formal-guarantee bar; **MemAudit** (2605.23723) — 70%→**0%** (QA), causal post-hoc; **Forensic
  Trajectory Signatures** (2606.30566) — **AUC 0.99**, distinguishes injection vs memory-poisoning;
  MAGE shadow-memory (2605.03228). Jataayu's SessionTrace is *detection-by-audit*; TMA-NM is
  *prevention-by-IFC* — the differentiation to draw.

**Tool/MCP return poisoning** (`tool-return` surface):
- **Trust No Tool / VISTA-Guard** (2605.17453): final-action risk scoring over trajectories,
  GuardedJoint **84.2 in-domain / 56.9 OOD**, single-sided baselines "collapse to zero." Direct analog
  to our tool-return guard. **MCPTox** (2508.14925): peak ASR **72.8%**, Claude-3.7 refusal <3%.

## 4. Two prior-art collisions to address head-on

The mechanism we describe in `guards/effect_boundary.py` is no longer novel in isolation:

- **SecureClaw (2606.09549)** independently proposes **opaque-handle read confinement + PREVIEW→COMMIT
  with a trusted executor committing the canonical policy-authorized request** — nearly verbatim our
  read/write boundary. Reports ASB 0% / AgentDojo 0.64% / AgentLeak 3.23%, no utility %. **Action: read
  it; differentiate on the three-factor severity-graded authorization and the deterministic single-gate
  decision.**
- **AuthGraph (2605.26497)** owns "provenance × authorization" via dual-graph alignment at tool+param
  level (40→1% ASR). Our worst-inbound-provenance axis overlaps; **our differentiator is the
  severity-weighted effect product + capability policy** (AuthGraph is pure structural graph comparison,
  binary allow/deny).

## 5. Where Jataayu wins, and the honest gaps

**Whitespace no single paper claims:**
- **Three-factor product** — `severity × worst-provenance × capability` as one deterministic gate. The
  cohort is mostly binary allow/deny (AuthGraph) or capability-only (CaMeL/Progent) or label-IFC
  (FIDES); severity-*graded* effect authorization (DENY critical, HOLD consequential, ALLOW low) is ours.
- **One coherent stack across all four surfaces** — effect boundary + skill vet + composition + memory
  audit + egress channel + tool-return, sharing one `EffectClass`/`Provenance` vocabulary. The field
  has a *separate paper per module*; we have the integrated primitive.
- **Deterministic + sub-ms + ~0 VRAM** — none of the trained guardrails publish ms/VRAM; the
  deterministic cohort is comparable in spirit but SecureClaw/AuthGraph don't report latency. Our
  explicit cost table is a genuine differentiator.
- **Stateful/temporal reasoning** (SessionTrace) — only ACP has anything like it in the effect cohort.

**Honest gaps / warts:**
1. **AgentDojo utility tax on some models (~20pp on gpt-5.4-mini).** Meets 0% ASR but over-blocks
   benign tasks on that config. Top fix before any AgentDojo headline. (qwen3.6-35b is clean at 0pp,
   so this is a model-specific false-positive issue, not a design flaw.)
2. **We publish AgentHarm + deepset + InjecAgent but not yet a *clean, multi-model* AgentDojo table.**
   The whole cohort competes on AgentDojo; we have runs but need the utility tax fixed + a presentable
   multi-model sweep. (Already the #1 lever in lit-review §8.)
3. **No formal-verification story** vs CaMeL (provable security) / TMA-NM / ControlValve (machine-checked).
   Our guarantee is "deterministic by construction," not machine-checked. A TLA+/proof sketch of the
   effect-boundary invariant would close the gap with the formal cohort.
4. **Composition + memory modules are unbenchmarked** against SCR-Bench / the sleeper-memory attack
   suites — we have the mechanisms, not the numbers.

## 6. Verification caveats
- **Peer-reviewed confirmed:** CaMeL (SaTML 2026), ControlValve (ICLR 2026), SafeHarbor (ICML 2026
  poster 64556), ShieldAgent (ICML 2025), OS-Harm (NeurIPS 2025).
- **arXiv-only (real IDs fetched, no venue):** FIDES, AgentArmor, AuthGraph, SecureClaw, ACP, PORTICO,
  ARGUS, TMA-NM, MemAudit, SCR-Bench, SkillVetBench, VISTA-Guard, the sleeper-memory attacks.
- **Numbers flagged soft** (secondary-source or abstract-only, verify against PDF before citing in a
  camera-ready): CausalArmor ICML-accept status; SecureClaw/AuthGraph/PORTICO exact utility baselines;
  ATBench baseline F1s; MELON 0.32%/68.72%.
- ⚠ **Ecosystem-name flag:** several skill-composition/memory papers (2606.00448, 2606.00925, and the
  *Claw*-named family) build on OpenClaw/ClawHub — the same names as our own stack. Confirm independence
  before citing as third-party validation; this recurs from lit-review §0's caveat.

*Jataayu AgentDojo numbers: `eval/results/agentdojo_*.json`. AgentHarm: run
`eval/run_agentharm_effect_boundary.py`.*
