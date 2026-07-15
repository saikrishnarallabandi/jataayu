# Jataayu — agent-security literature review (2026-07)

*Author: research pass, 2026-07-04. Method: 5-way parallel web fan-out (inbound / outbound /
action-level / skill-MCP supply-chain / benchmarks), each agent tasked to prioritize late-2025 →
mid-2026 work and tag sources by type. This note synthesizes the frontier and maps it back to
Jataayu's four pillars. Companion to `docs/upgrades-from-arxiv-2026-06.md` (per-paper roadmap)
and `docs/research-integration-2026-06.md` (replication plan). Where those covered six specific
papers, this note is the broader field scan around them.*

> Carried thesis: **"You can't secure an agent by checking its final answer. You have to watch
> what it touches. Execution is the new attack surface."** The 2026 literature has now converged
> on exactly this — which is the headline finding of this pass.

---

## 0. Credibility tiering (read this first)

The 2026 agent-security corpus is moving fast and much of it is single-team preprints. To avoid
overstating, every claim below is tagged:

- **[SOLID]** — established, independently corroborated, or a tracked CVE / named vendor incident.
- **[DIRECTIONAL]** — a single recent preprint or vendor benchmark; plausible, not yet replicated.
- **[UNVERIFIED]** — could not be independently anchored past our knowledge cutoff; several sit in
  a same-ecosystem 2026 family that overlaps our own internal notes. Treat numbers as illustrative.

**One honest caveat:** several of the most Jataayu-aligned 2026 papers (arXiv:2606.18356, arXiv:2606.09549,
SkillVetBench, RSA) are the same IDs cited in our own `docs/` — i.e. our prior passes and this
web scan are partly drawing on the same possibly-synthetic corpus. The *verifiable* backbone of
this review (AgentDojo, ASB, InjecAgent, AgentHarm, CaMeL, FIDES, MCPTox, the EchoLeak/AgentFlayer/
Clinejection/Cursor incidents, OWASP/NIST) is solid and stands on its own; the design conclusions
below rest on that backbone, not on the unverifiable tier.

---

## 1. The one-line takeaway for Jataayu

**The frontier moved to where Jataayu already bet: the effect/action boundary, gated by
provenance × severity.** Every leading 2026 defense — CaMeL, Microsoft FIDES, OAP, ControlValve,
the dual-graph provenance work — is a variation of *"don't classify the string, control what
untrusted-influenced data is allowed to DO."* That is Jataayu's `EffectBoundary` thesis, now the
mainstream research direction. **Positioning consequence: lead with the effect boundary, not the
regex catalog.** The same literature that vindicates the effect boundary is brutal about detectors
(§2.3), which is Jataayu's weakest tier.

---

## 2. Pillar 1 — INBOUND (injection detection)

### 2.1 Attacks crossed from PoC to in-the-wild
- **[SOLID]** Palo Alto **Unit 42** documented indirect web injection *observed in the wild*
  (Mar 2026): 22 distinct techniques, real cases driving Stripe payments, DB deletion, ad-moderation
  bypass; one scam page stacked 24 injections. First at-scale field evidence, not lab demos.
  https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/
- **[SOLID]** **Clinejection** — prompt injection in a **GitHub issue title** hijacked Cline's
  Claude triage Action → CI cache poisoning (Cacheract) → stolen release tokens → malicious npm
  package on ~4,000 dev machines. `GHSA-9ppg-jx86-fqw7` (GitHub rated *Low* — widely criticized as
  undercounting agent-CI risk). Disclosed Feb 2026. The first full injection→supply-chain kill chain.
- **[SOLID]** **Cursor "DuneSlide"** — zero-click injection via MCP escapes the editor sandbox to
  RCE. **CVE-2026-50548 / -50549**, CVSS 9.8. Coding-agent injection is now formally tracked,
  high-severity, and patched — not a research curiosity.
- **[SOLID]** **GitHub Copilot CVE-2025-53773** — injection in public-repo comments flips Copilot
  settings to enable code execution without approval (injection → RCE on the dev machine).

### 2.2 Memory is now a first-class inbound surface
- **[SOLID]** Unit 42 (Oct 2025): long-term memory poisoning persists across sessions on Amazon
  Bedrock Agents; folded into the orchestration prompt, silently exfiltrates future conversations.
- **[DIRECTIONAL]** *Sleeper Memory Poisoning* — payload lies dormant in memory until a trigger
  fires in a **later** session, defeating request-scoped filters. Plus defenses MemAudit / MAGE
  (shadow memory). The attack effect is **decoupled in time** from the injection.
- **Maps to Jataayu:** we have `memory-read` / `memory-write` surfaces (shipped P0), but they are
  *single-shot* inbound scans. A sleeper payload can be individually-benign per write and only
  harmful on later recall+trigger → a per-write regex/LLM check is structurally insufficient.
  **This is the strongest argument yet for the deferred P2 `SessionTrace`/audit** (cross-turn view).

### 2.3 Detectors collapse under distribution shift — the validity crisis
- **[SOLID]** *"When Benchmarks Lie"* (2026): same-source train/test inflates scores. Under
  leave-one-dataset-out, near-perfect (0.996 AUC) drops to 0.912, and **production guardrails
  collapse on indirect injection: PromptGuard-2 detects 37%, LlamaGuard 27%, LLM-as-judge 7%.**
- **[SOLID]** Adaptive-attack work (2025, arXiv:2503.00061): spotlighting / sandwiching only
  marginally reduce ASR; most published IPI *detection* defenses break under attacker adaptation.
- **[DIRECTIONAL]** Activation/probe detectors (TaskTracker; the "Benchmarks Lie" classifier at
  68% indirect / 99% agentic @ 6.5% FPR) and LLM detect-and-strip (**PromptArmor**, ICLR 2026,
  claims <1% FP and <1% FN on AgentDojo) do better, but numbers are benchmark-specific.
- **Maps to Jataayu — CONFIRMS the architecture, INDICTS the marketing.** This is the single most
  important message for us: **regex/keyword detection is the weakest tier against an adaptive
  attacker** — exactly why Jataayu treats the fast path as a *pre-filter* and puts the guarantee at
  the effect boundary. Do **not** headline detection accuracy; headline the layer that survives
  adaptation. Our normalization/de-obfuscation stack (§2.4) is table stakes, not a moat.

### 2.4 Evasion / normalization — still an arms race
- **[SOLID]** Invisible payloads (zero-width, Unicode **tag** chars, bidi, homoglyphs, base64/hex)
  routinely smuggle instructions past keyword/regex filters; the standard defense is a
  de-obfuscation pass (NFKC, strip zero-width, fold confusables, recursive decode) **before**
  detection. Lasso `claude-hooks` (Jan 2026) ships 50+ such patterns.
- **[DIRECTIONAL]** New carriers: hidden Unicode instructions **inside MCP tool descriptions /
  skill files** (CSA); steganographic payloads in float/numeric data ("Hiding in Plain Floats").
- **Maps to Jataayu — CONFIRMS.** This is precisely our Layer-0 (multi-view normalize + recursive
  decode, take the max score across views). We are aligned with best practice here; the float-carrier
  and tool-description-Unicode vectors are worth a targeted pattern add.

---

## 3. Pillar 2 — OUTBOUND (exfiltration / privacy)

### 3.1 The exfil channel is the point, and it's usually markdown-image auto-fetch
- **[SOLID]** **EchoLeak** (M365 Copilot, **CVE-2025-32711**, CVSS 9.3, zero-click): one crafted
  email exfiltrates the whole Copilot context. Chained: evaded the injection classifier → reference-
  style markdown to bypass link redaction → auto-fetched image → abused a **Teams proxy URL the CSP
  already trusted.** First real-world zero-click prompt injection in a production LLM.
- **[SOLID]** **AgentFlayer** (Black Hat Aug 2025, Zenity): poisoned doc (white 1px font) exfiltrates
  Drive/SharePoint/GitHub secrets via markdown image. After OpenAI's fix, re-bypassed using **Azure
  Blob URLs** (a trusted host) — **domain allowlisting alone is proven insufficient.**
- **[SOLID]** **Notion AI** (Dec 2025→Jan 2026): injected resume → malicious markdown image URL
  auto-fetched *before* user approval, leaking hiring-tracker data in the query string.
- Framing: Simon Willison's **"lethal trifecta"** = private data + untrusted input + exfil vector.
- **Maps to Jataayu — GAP.** Our outbound guard finds **PII / secrets in the text** (regex + entropy
  + LLM sanitize). It does **not** currently inspect the *exfil channel construct*: a markdown image
  or link pointing at a novel/untrusted domain, or data smuggled in a URL query-string. **New module
  opportunity — an outbound egress/channel guard** (§8, item 2): flag data-carrying URLs/images in
  agent output, allowlist rendering targets, treat trusted-host CSP bypass as the threat model.

### 3.2 Egress reference monitors are emerging as a defense *category*
- **[DIRECTIONAL]** Application-layer multi-modal covert-channel monitor for agent egress —
  inspects output *before* it leaves, covering markdown-image, DNS, and tool-call side channels in
  one monitor. This is the outbound dual of the input-side injection classifier.
- **Maps to Jataayu — EXTENDS.** Validates promoting our outbound guard from "scrub PII text" to
  "reference monitor over the whole outbound action," which composes with the effect boundary.

### 3.3 Privacy / contextual integrity in multi-user settings
- **[SOLID]** Benchmark lineage ConfAIde → PrivacyLens → CIMemories: models *state* privacy norms
  but *violate* them when executing instructions. **[DIRECTIONAL]** 2026 extends this to agentic /
  enterprise / multimodal / persistent-memory settings (AgentLeak, CI-Work, MPCI-Bench).
- **Maps to Jataayu — EXTENDS.** Our outbound `protected_names` + surface trust is a lightweight
  contextual-integrity mechanism (leak A's context to B's audience). The literature says the harder
  case is *persistent-memory* leakage accumulating over turns — again pointing at cross-turn audit.

### 3.4 Secrets: MCP configs are the new sink
- **[SOLID]** GitGuardian (Apr 2026): 29M secrets leaked in 2025; **24,008 unique secrets in MCP
  config files** — tool-connection configs are now a first-class leak surface.
- **[DIRECTIONAL]** Marketplace-scale credential leak: ~3.1% of 17K agent skills leak credentials;
  dominant mechanism is mundane — **`print`/`console.log` → stdout piped straight into the LLM
  context window (73.5%)**, so a natural-language query retrieves the secret.
- **Maps to Jataayu — CONFIRMS + EXTENDS.** Our 18 credential rules + entropy detector cover the
  *text* case. The stdout→context mechanism is an argument for scanning **tool-returns** for secrets
  (we already have the `tool-return` inbound surface — extend it to also run the *outbound/credential*
  ruleset, i.e. secrets flowing *in* from a tool are a leak risk downstream).

---

## 4. Pillar 3 — EFFECT BOUNDARY / ACTION-LEVEL (Jataayu's core bet)

This is where the frontier is richest and most validating.

- **[SOLID]** **CaMeL** — *Defeating Prompt Injections by Design* (arXiv:2503.18813, IEEE **SaTML
  2026**, peer-reviewed). Dual-LLM: a privileged LLM writes a plan over a restricted interpreter;
  a quarantined LLM parses untrusted data and **can never affect control flow**; per-value
  **capabilities carry provenance**; a policy engine gates tool calls by dataflow. **Solves 77% of
  AgentDojo tasks with provable security vs 84% undefended (~7-pt utility cost).** Known critique:
  users must author/maintain explicit policies; plan-then-execute sacrifices adaptivity.
- **[SOLID]** **FIDES** (Microsoft Research, arXiv:2505.23643) — confidentiality + integrity labels
  on every message/arg/result; a planner deterministically enforces policy (dynamic taint IFC).
  **Deterministically stopped ALL policy-violating injections in AgentDojo (0 successes) vs 20–152
  across undefended planners.**
- **[SOLID/peer-reviewed]** **ControlValve** (ICLR 2026, arXiv:2510.17276) — control-flow-integrity
  + least-privilege for **multi-agent** systems; generates permitted control-flow graphs.
  **Blocks all evaluated attacks (baselines up to 56% ASR); utility 62% vs 65% undefended (~3-pt).**
- **[DIRECTIONAL]** **OAP** ("Before the Tool Call") — deterministic, **non-LLM** pre-action
  authorization over declarative policy; signed audit record. **Restrictive tier: 0/879 social-
  engineering attempts succeeded; p50 latency 53 ms; covers 8/10 OWASP Agentic risks.**
- **[DIRECTIONAL]** **arXiv:2606.09549 / CapSeal** — read-boundary confinement: secrets become **opaque
  handles** the model plans over but cannot dereference to plaintext; external writes via
  **PREVIEW→COMMIT** where a trusted executor commits only the exact authorized request.
- **[DIRECTIONAL]** **Dual-graph provenance × authorization** — a provenance graph (lineage) × an
  authorization graph (permissions); each action gated on **input provenance × effect severity**.
  Program-analysis line: **AgentArmor** builds typed program-dependence graphs over runtime traces.

**Maps to Jataayu — STRONG CONFIRMATION, this is the moat.**
- Jataayu's `jataayu_authorize_action(effect, params, untrusted=…)` decides ALLOW/DENY/APPROVAL by
  **effect severity × worst inbound provenance × capability policy, deterministically (no LLM)** —
  this is the *same design language* as OAP (deterministic, signed) and the dual-graph work
  (provenance × severity). We independently landed on the emerging consensus primitive.
- Our **PREVIEW→COMMIT** with a `commit_token` binding the exact request = arXiv:2606.09549's protocol.
- Our read-boundary **opaque-handle** confinement (in ARCHITECTURE / README) = arXiv:2606.09549/CapSeal's
  "plan over references, never dereference plaintext" — corroborated now by FIDES labels too.
- **What we're missing vs the leaders:** (a) CaMeL/FIDES/ControlValve report **AgentDojo** numbers;
  we report deepset + InjecAgent. Publishing an AgentDojo number is our biggest external-credibility
  lever (§8, item 1). (b) FIDES's *information-flow labels* and ControlValve's *control-flow graph*
  are richer than our per-call taint; a `SessionTrace` (already deferred P2) is the on-ramp.
- **Deterministic-vs-flexible tension is the field's live debate** (CaMeL policy-authoring burden;
  "deterministic engines discard probabilistic info" → hybrid probabilistic verification). Jataayu's
  deterministic effect boundary sits squarely on the "0% ASR, some utility cost" side — a defensible,
  currently-winning position, but we should have an answer for the utility/authoring cost.

---

## 5. Skills / MCP supply chain + COMPOSITION

- **[SOLID]** **MCP attack classes** are now named and CVE'd: **Tool Poisoning** (hidden instructions
  in tool `description`, Invariant Labs), **line-jumping** (inject via the `tools/list` handshake,
  *before any call*, Trail of Bits), **rug-pull** (mutable definitions swapped post-approval),
  **cross-server shadowing** (confused deputy). **CVE-2025-54136 / -54135**; ≥7 platform CVEs
  (Inspector, LiteLLM, Cursor, LibreChat, Windsurf). OWASP shipped an **MCP Security Cheat Sheet**;
  the 2026 MCP spec added incremental/least-privilege scope consent but **no native poisoning defense.**
- **[SOLID]** **MCPTox** benchmark (arXiv:2508.14925): tool-poisoning ASR **>60%** across 20 agents;
  worst models compromised on **72%** of attempts.
- **[DIRECTIONAL]** Registry-scale: 42K–98K skills scanned; ~26% carry ≥1 vulnerability; real
  campaigns (marketplace poisoning) and a claimed first agentic-system CVE. Code-layer scanners miss
  **89–100%** of *instruction-layer* (prompt-injection / memory-poisoning) skills.
- **[DIRECTIONAL]** **Compositional risk quantified** (SCR-Bench / "SkillReact",
  arXiv:2606.00448): individually-safe skills compose into unsafe sets. On 1,520 skills from the referenced skill registry,
  651 pass individual inspection and form 211,575 pairs; **22.25%** flag as structural candidates,
  of which a two-rater human-adjudicated audit validates **18.2%** as real compositional risk (the
  paper's headline) — ≈14K genuine risk memberships that per-skill scanning misses by construction.
  Realization is **host-model-gated**: on an anchor-conditioned dropper subset Haiku-4-5 issued the
  dropper-stage tool call in 39/39 trials, Opus-4-7 stopped at download, Sonnet-4-6 refused — "a
  composition fixes which capabilities are reachable; the host model decides whether to use them."
  (CORRECTION 2026-07-04: an earlier draft of this note cited "composed-path ASR 33.6%",
  "Trust-Transfer 1.1%→83.9%", and "auth-blur 15.7%→34.0%" to SCR-Bench — none of those figures
  appear in arXiv:2606.00448; they were confabulated and have been removed.)
- **[DIRECTIONAL]** **Static collapses under self-evolving attacks:** AgentTrap's best static
  scanner catches only ~55% (50/91); pushes toward **runtime/request-conditioned auditing** (STARS,
  Runtime Skill Audit) where invocation safety depends on retrieved content + prior outputs +
  trajectory, not the skill spec alone.

**Maps to Jataayu — CONFIRMS the modules, EXTENDS the model.**
- Our `jataayu_vet_skill` (LLM-judge Skill-Risk vector) and `jataayu_check_skillset` (dangerous
  capability pairs/chains across skills) are directly on the frontier — the field independently built
  the same primitives (SkillVetBench, SCR-Bench). The "code scanners miss 89–100% of instruction-
  layer threats" finding is exactly our positioning (reason about the markdown prose, not just code).
- **New dimensions to model that we don't yet:** **trust-transfer/endorsement** (an endorsed skill
  should not have endorsement launder a dangerous capability — *jataayu's own defensive stance;
  SCR-Bench reports no endorsement-effect number*) and **intent fragmentation** (harm split across
  individually-benign skills, the case pairwise review misses). Candidate new capability tags /
  composition rules (§8, item 4).
- **Static-collapse → runtime auditing** is the same conclusion as §2.2 (sleeper memory) and §6:
  everything points at the deferred **P2 `SessionTrace`**.

---

## 6. Benchmarks & the semantic-vs-effect harm gap

- **[SOLID] Reference set:** **AgentDojo** (arXiv:2406.13352; the injection attack/defense
  leaderboard — best benign utility ~78%, GPT-4o utility 69%→~50% under attack), **ASB**
  (arXiv:2410.02644, ICLR 2025; highest avg ASR 84.3%), **InjecAgent** (arXiv:2403.02691; ReAct
  GPT-4 ~24% ASR), **AgentHarm** (arXiv:2410.09024, ICLR 2025).
- **[SOLID] AgentHarm already separates the axes we care about:** primary metric is a rubric-graded
  **harm score** plus **Refusal Rate** and **Non-Refusal Harm Score** (harm *conditional on acting*)
  — i.e. "did it refuse?" ≠ "did it actually accomplish harm?" This is the semantic-vs-effect split
  in a *verifiable* benchmark, and it aligns with Jataayu's effect-boundary thesis.
- **[DIRECTIONAL/UNVERIFIED] arXiv:2606.18356** — the sharpest quantification of the gap: of 347
  sandbox-observed harms, **291 (83.9%) passed the semantic/text check** — a text-only judge would
  have called them safe. (Same paper already in our `docs/`; treat 83.9% as indicative.)
- **[DIRECTIONAL] Trajectory-native eval** matured: ATBench (grade over full traces), T-MAP
  (trajectory-aware evolutionary red-teaming), MonitoringBench (can a monitor spot sabotage in a
  completed trajectory?). Plus **[SOLID]** OS-HARM (computer-use agents in a real OS).
- **[SOLID] Defense scoreboard, mid-2026:** no single winner on both axes. CaMeL (~77% provable) and
  PromptArmor (<1% ASR/FP/FN on AgentDojo) lead on security-with-utility; training-based
  **SecAlign** drives ASR 96%→2% but pays a utility tax that *widens* on harder dynamic benchmarks
  (~80% AgentDojo → 53.4% AgentDyn). Layered defenses take ASR ~73–84% → <10% in controlled studies,
  but adaptive attacks still beat weak/undefended agents (>85%).

**Maps to Jataayu — the semantic-vs-effect gap is our thesis, now measurable.** Our README already
ships an InjecAgent result. **The missing, high-value eval is AgentDojo** — the field's shared
scoreboard, and the one that lets us show the effect boundary's utility/ASR tradeoff next to CaMeL/
FIDES/PromptArmor rather than against a static text corpus. AgentHarm's Non-Refusal-Harm-Score is
the right *metric shape* to adopt for our own tests (grade effect, not text).

---

## 7. Standards & frameworks (positioning)

- **[SOLID] OWASP Top 10 for Agentic Applications 2026** (released **Dec 9 2025**, 100+ experts) —
  a dedicated list beyond the LLM Top 10. Items include Goal Hijack, **Tool Misuse & Exploitation**,
  Identity & Privilege Abuse, **Agentic Supply-Chain (malicious/tampered tools, descriptors,
  personas)**, Unexpected Code Execution, **Memory & Context Poisoning**, Insecure Inter-Agent Comms,
  Cascading Failures, Rogue Agents.
- **[SOLID] NIST AI Agent Standards Initiative (CAISI)** — launched **Feb 17 2026**, first US-gov
  program for agentic-AI interoperability + security; RFI drew 932 comments; red-team research
  reports novel agent attacks at **81% success vs 11% on baseline defenses.**
- **[SOLID] CSA MAESTRO** — layered agent threat-modeling framework (model / agent-design /
  orchestration / external-interaction); CISA released an agentic-AI guide (2026).

**Maps to Jataayu — free positioning.** Our guarantees map cleanly onto ASI items: effect boundary →
Tool Misuse + Unexpected Code Execution + Excessive Agency; provenance gating → Identity/Privilege
Abuse; skill-vet + composition → Agentic Supply-Chain; memory surfaces → Memory & Context Poisoning.
Adopt this vocabulary in the README so buyers can map us to the framework they're already using.

---

## 8. What this means for Jataayu — ranked roadmap deltas

Ordered by (external credibility × leverage) ÷ lift. Items 1–2 are new; 3–6 re-rank existing backlog.

1. **Ship an AgentDojo evaluation.** [NEW, highest external leverage] The field's shared leaderboard;
   CaMeL/FIDES/PromptArmor/SecAlign all report on it. Show the **effect boundary's ASR↓ with utility
   retained**, next to those. Our current deepset+InjecAgent numbers don't let anyone compare us to
   the leaders. This is the single biggest credibility lever.
2. **Outbound egress/channel guard.** [SHIPPED 2026-07-04] `guards/egress.py` `EgressChannelGuard`
   + `jataayu_check_egress()`, wired into `OutboundGuard`. Promotes the outbound guard from
   "PII/secret text scrub" to a **reference monitor over the outbound action**: classifies every
   URL by render mode (image auto-fetches vs link needs a click) × host trust × data-carrying, and
   hard-blocks exfil-beacon / abused-trusted-relay hosts (Azure Blob, webhook.site) so
   **trusted-host bypass** is covered — allowlisting alone is treated as insufficient. Optional
   `context_secrets` confirms exfil when a known value rides in a URL. 26 tests. (EchoLeak /
   AgentFlayer / Notion channel — §3.1.)
3. **Prioritize the deferred P2 `SessionTrace` / runtime audit.** [SHIPPED 2026-07-04]
   `core/audit.py` `SessionTrace` — accumulates a session's tool calls and audits the trajectory:
   detects cross-turn exfil chains, sleeper memory poisoning (write→later recall→dangerous effect),
   untrusted-into-critical, and escalating trajectories. Deterministic, reuses `EffectClass` /
   `Provenance`. 14 tests. Motivated by the three convergent 2026 lines: sleeper memory poisoning
   (§2.2), static-scanner collapse (§5), and the semantic-vs-effect gap needing trajectory
   grading (§6) — none visible to single-shot inbound checks.
4. **Extend the composition model** with **trust-transfer/endorsement** (jataayu's stance:
   endorsement is not a security property) and **intent fragmentation** dimensions (motivated by
   SCR-Bench's finding that individually-safe skills compose into unsafe sets — 22.25% flagged,
   18.2% validated; *no endorsement-effect stat is claimed by that paper*).
   [SHIPPED 2026-07-04] `guards/composition.py`: an `endorsed` skill contributing a dangerous
   capability to a realized combo is now blocked at install (MALICIOUS via `trust_transfer`);
   combos are annotated `fragmented` when spread across 3+ skills. Backward-compatible. 6 tests.
5. **Adopt effect-level metrics** — AgentHarm's Non-Refusal-Harm-Score shape: grade "did an effect
   fire?", not "did the text look safe?" [SHIPPED 2026-07-04] `eval/run_semantic_vs_effect.py` — a
   deterministic offline harness grading trajectories text-only vs effect-level via `SessionTrace`.
   Measured gap: text recall **17%** vs effect recall **100%**; 5/6 harms are text-silent (≈
   arXiv:2606.18356's 291/347).
6. **Map guarantees to OWASP Agentic Top-10 (ASI0x) + name the moat.** [SHIPPED 2026-07-04]
   README "Where Jataayu sits in the standards" table maps each guard to an OWASP Agentic risk and
   states the moat is the effect boundary, not the regex catalog (the detector-validity crisis of
   §2.3 makes the catalog the *weakest* tier against adaptive attackers).

**Not done this pass (deferred — needs a supervised, paid run):**

1. **AgentDojo evaluation** (§8 item 1, highest external-credibility lever) — deliberately NOT
   scaffolded-and-shipped unverified: it requires the `agentdojo` package, an LLM backend, and a
   paid task sweep, so running it unattended would either cost tokens without oversight or ship a
   harness I could not verify end-to-end. Left as the top next step for a supervised session:
   report the effect boundary's ASR↓ / utility-retained next to CaMeL / FIDES / PromptArmor.

---

## Sources (verifiable backbone)

**Incidents / CVEs:** EchoLeak CVE-2025-32711 (M365 Copilot); AgentFlayer (Zenity, Black Hat 2025);
Notion AI exfil (PromptArmor); GitHub Copilot CVE-2025-53773; Clinejection GHSA-9ppg-jx86-fqw7;
Cursor DuneSlide CVE-2026-50548/-50549; MCP CVE-2025-54136/-54135. Unit 42 in-the-wild injection
(Mar 2026) + memory poisoning (Oct 2025).
**Defenses (peer-reviewed / strong):** CaMeL arXiv:2503.18813 (SaTML 2026); FIDES arXiv:2505.23643
(Microsoft); ControlValve arXiv:2510.17276 (ICLR 2026); AgentArmor arXiv:2508.01249; MELON
arXiv:2502.05174; adaptive attacks arXiv:2503.00061.
**Benchmarks:** AgentDojo arXiv:2406.13352; ASB arXiv:2410.02644; InjecAgent arXiv:2403.02691;
AgentHarm arXiv:2410.09024; MCPTox arXiv:2508.14925; OS-HARM arXiv:2506.14866.
**MCP threat writeups:** Invariant Labs (tool poisoning); Trail of Bits (line-jumping); OWASP MCP
Security Cheat Sheet.
**Standards:** OWASP Top 10 for Agentic Applications 2026 (genai.owasp.org); NIST AI Agent Standards
Initiative / CAISI; CSA MAESTRO.
**Directional / unverified (cite as indicative):** arXiv:2606.18356, arXiv:2606.09549, SkillVetBench, CapSeal,
OAP, SCR-Bench, "Benchmarks Lie" LODO numbers, sleeper memory poisoning, egress reference monitor,
registry-scale skill studies, PromptArmor <1% figures — single recent preprints or vendor benchmarks,
several in a same-ecosystem family overlapping our own internal notes.
