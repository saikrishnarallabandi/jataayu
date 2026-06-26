# Jataayu — research integration & replication notes (2026-06)

*Author: research-integration pass, 2026-06-26. Analysis + planning only — no code in this
pass. Companion to `docs/upgrades-from-arxiv-2026-06.md` (the per-paper gap → upgrade roadmap).
This doc adds two things that file does not: (1) a measured **active-status** finding for the
live OpenClaw deployment, and (2) a **replication assessment** — for each paper, can we test the
finding on our OWN OpenClaw conversation data, with corpus sizes and a metric.*

> Thesis carried over from the reel/notes: *"You can't secure an agent by checking its final
> answer. You have to watch what it touches. Execution is the new attack surface."*

---

## 0. Active status — is Jataayu actually intercepting?

**Verdict: ENABLED but PASSIVE. Jataayu does not automatically intercept any inbound or outbound
message in the live OpenClaw gateway today.** It is installed, registered, and importable; the
guards work when called; but nothing in the live message path calls them automatically, and in
the entire trajectory history the agent has never called them on its own.

Evidence:

| Check | Finding |
|---|---|
| Plugin registered/enabled | `openclaw.json → plugins.entries.jataayu = {"enabled": true}`; load path `/home/srallaba/.openclaw/plugins/jataayu`. |
| Integration shape | `plugins/jataayu/index.js` calls `api.registerTool()` **twice** — `jataayu_check_inbound`, `jataayu_check_outbound` — each `execFile`-ing the `judith_env` Python into `/home2/srallaba/projects/jataayu` and running `InboundGuard.check` / `OutboundGuard.check`. |
| Is there an auto-hook? | **No.** The only `api.*` calls in the plugin are `api.pluginConfig` and two `registerTool`. No `onMessage` / `beforeSend` / `onInbound` / interceptor. Guards run only if the **model chooses** to call the tool (tool descriptions say "Always call this before acting…" — i.e. prompt compliance, not enforcement). |
| Actual runtime invocations | **0 of 20,528 `tool.call` events** name a Jataayu tool. (225 lines match `jataayu_check`, but all are `bash` commands from dev work — `data.name == "bash"`, the string is in `arguments`.) |
| Enforcement, even if called | `blockOnInboundHigh` defaults `false` **and is never read** in `index.js`. Outbound tool runs `use_llm=False` with a hardcoded protected list (family names + portfolio tickers). Result is advisory text returned to the model — nothing is blocked. |
| MCP gateway enforcement path | `integrations/mcp_gateway.py`'s `before_tool_call` proxy is **not deployed** — no process running; port 8765 is OpenClaw's own HTTPS gateway (returns "HTTP request to an HTTPS server"), not Jataayu's plain-HTTP gateway. |
| OpenClaw's own defenses (orthogonal) | OpenClaw already wraps external content with a `SECURITY NOTICE: … EXTERNAL, UNTRUSTED source` preamble and gates shell via `exec-approvals.json`. These are OpenClaw mechanisms, not Jataayu. |

**Implication for this doc:** the *capability* exists and is sound (below), but to make any of the
paper-driven upgrades matter, Jataayu first needs a real interception point — either an OpenClaw
plugin **hook** (auto-run inbound on received messages / outbound on drafts) or the **MCP gateway**
in front of tool calls. That wiring is itself the first deferred implementation item.

---

## 1. What Jataayu detects today (capability baseline)

Faithful summary of the current code, so the upgrades below are anchored to real modules.

**Inbound — `guards/inbound.py` (`InboundGuard`)**
- Fast path: **55+ compiled regex patterns** (`INJECTION_PATTERNS`) across 8 `ThreatType`s
  (`PROMPT_INJECTION`, `COMMAND_INJECTION`, `SOCIAL_ENGINEERING`, `UNICODE_BYPASS`,
  `ENCODING_OBFUSCATION`, plus MCP-/SSRF-/exfil-shaped patterns folded into those types):
  instruction override, role-switch/DAN, fake system tokens (`<|im_start|>`, `[SYSTEM]`),
  delimiter & history-poisoning, prompt-leak, MCP tool-description/name-shadowing,
  curl-pipe-shell / reverse shells / privilege-esc, SSRF (IMDS 169.254.169.254), exfil
  (`cat ~/.ssh`, env-var transmit), unicode RTL/zero-width/tag chars + homoglyph scan,
  base64/hex/URL-encoding.
- Markdown-aware NLP layer (`_markdown_nlp_check`): injection keywords hidden in headings /
  list items / non-code paragraphs (code blocks excluded).
- Surface multipliers (`SURFACE_MULTIPLIERS`) scale scores (github-issue ×1.2 … internal ×0.5).
- Slow path: LLM-as-judge (`_slow_path` + `core/engine.py LLMBackend`, ollama/openai/anthropic/
  openclaw). Invoked only when fast-path `risk ≥ llm_threshold` (0.35) and below the 0.90
  short-circuit; returns a structured JSON verdict.
- `_score_to_level`: clean/low/medium/high/blocked at 0.20/0.45/0.70/0.90.

**Outbound — `guards/outbound.py` (`OutboundGuard`, `PrivacyConfig`)**
- PII patterns (`_PII_PATTERNS`) over categories `minors_info / health / financial /
  home_address / relationships`; **protected-name** scanning (capped below BLOCKED so it can be
  sanitized); **18 credential rules** (`_CREDENTIAL_PATTERNS`, Aguara CRED_001–017: OpenAI/
  Anthropic/AWS/GitHub/GCP/Stripe/SendGrid/Twilio keys, private-key blocks, DB URIs, JWT,
  shell `export`, bearer/HMAC); optional Shannon-entropy secret detector.
- Outbound surface multipliers (public ×1.3 … internal ×0.3).
- Remediation: `_regex_redact` (no-LLM fallback) and `_llm_sanitize` (surgical rewrite, or
  `BLOCKED` when the whole message is sensitive).

**Core / surfaces / integrations**
- `core/taint.py` `TaintTracker` — tainted-data → dangerous-sink flow.
- `integrations/mcp_gateway.py` `JataayuMCPGateway.before_tool_call` — runs `InboundGuard` on
  tool-call params + inherent `_SINK_BASE_SCORES` (bash/exec/shell…), blocks at
  `block_threshold` (0.7). **Present but not deployed.**
- `surfaces/profiles.py` — per-surface `trust_level` / `inbound_strict` / `outbound_strict` /
  `risk_multiplier` (the right place to add new surfaces).
- Public entry points: `api.py` (`jataayu_check_inbound/outbound`), `convenience.py`,
  `integrations/cli.py`.

---

## 2. Per-paper: finding → maps-to-Jataayu → integration sketch [DEFERRED] → replication on our data

For each paper: the core finding (from `docs/upgrades-from-arxiv-2026-06.md` + known summaries),
how it touches Jataayu, the integration sketch (NOT to be implemented in this pass), and the
replication experiment we could run on our own OpenClaw trajectories.

### P1 — SkillVetBench · arXiv:2606.15899 (talk paper)
**Finding.** Community skills are an unvetted install-time surface; static/code scanners miss
**89–100%** of instruction-layer threats. An LLM-as-Judge with a multi-dimension risk score
(SARS) caught 78/78 malicious skills with zero false negatives.
**Maps to Jataayu.** No skill-vetting concept; `InboundGuard` guards runtime content, not skill
manifests. The slow-path LLM judge (`core/engine.py`) is already the needed primitive.
**Integration sketch [DEFERRED].** `guards/skill_vet.py` + `jataayu vet-skill <path>`: feed
SKILL.md + code + tool defs to an LLM judge scoring a Skill-Risk vector (`instruction_hijack`,
`data_exfil`, `memory_poisoning`, `capability_escalation`, `unexpected_side_effects`) → SAFE/
REVIEW/MALICIOUS; cheap pattern pre-filter first.
**Replication on our data — LIMITED.** Corpus = our **own installed skills/plugins**:
`plugins/{faiss-memory, flite3-tts, jataayu, linkedin-connector}` + workspace `SKILL.md` /
`SOUL.md` / subagents. That's a single-digit benign set — good for a **false-positive** sanity
pass (does the judge keep our real skills SAFE?), not a TPR benchmark. To get any positives we'd
inject a few synthetic malicious skills. **Verdict: feasible only as a small FPR demo + synthetic.**

### P2 — Runtime Skill Audit (RSA) · arXiv:2606.11671 (talk paper)
**Finding.** A skill benign statically can turn harmful only when invoked; static detectors
**collapse after 1–2 rounds** of self-evolving attacks, while runtime trace auditing held at
~90% accuracy / 88% TPR.
**Maps to Jataayu.** Fast path is static regex (brittle exactly where the paper says);
`before_tool_call` is per-call with no accumulated behavioral profile.
**Integration sketch [DEFERRED].** `core/audit.py` with a `SessionTrace` that `mcp_gateway`
appends each tool call to; profile fs/net/exec/memory per skill; `jataayu audit <session>`.
**Replication on our data — FEASIBLE (strong).** We can build `SessionTrace` **offline** from
trajectories: per `threadId/turnId`, the full `tool.call → tool.result → assistantTexts` chain is
present. Corpus: **20,490 tool.call events, 2,602 sessions with ≥1 risky call**. Experiment:
profile each session over fs/net/exec/memory interfaces; show that trace evidence flags
consequential sessions a static/final-text view misses. **Metric:** risky-session recall of the
trace profiler vs a final-text baseline. **Effort: medium; data ready.**

### P3 — When Safe Skills Collide · arXiv:2606.00448 (docs file, not a talk paper)
**Finding.** Individually-safe skills compose into unsafe sets; per-skill scanning misses ~14K
genuine risk memberships in one registry by construction; realization gated by host-model
disposition. Fix: install-time compositional checks + capability isolation.
**Maps to Jataayu.** Every check is single-item; no cross-skill reasoning; no capability
allowlist in `config/policy.py`.
**Integration sketch [DEFERRED].** `jataayu_check_skillset(installed_skills) → CompositionRisk`:
capability-tag skills (from P1), flag dangerous pairs/chains (`reads_secrets+network_write`,
`fs_write+exec`, `memory_write+instruction_follower`); wire allowlists into `config/policy.py`.
**Replication on our data — LIMITED / illustrative.** Only ~4 installed plugins. But the actual
capability graph is real and demonstrable: `bash` (exec/fs_write) + `message`/`sessions_send`
(network_write) = exfil chain; `faiss-memory` (memory_write) + any instruction-following tool =
poisoning vector. **Verdict: feasible as a small worked example on our real plugin set; not a
14K-scale benchmark.**

### P4 — SafeClawBench · arXiv:2606.18356 (talk paper)
**Finding.** Separating *semantic acceptance* vs *audit-evidence* vs *sandbox-observed* harm
matters: **291 of 347** real sandbox harms occurred in cases that **passed the semantic check**.
Text-level grading badly undercounts real harm.
**Maps to Jataayu.** Inbound scoring and outbound BLOCK are semantic/text-level; our own
`tests/` grade on text outcomes; no "did an effect occur" signal.
**Integration sketch [DEFERRED].** Adopt three staged endpoints (semantic-accept / audit-evidence
/ sandbox-effect) in `tests/`; add an effect-observation layer in `core/audit.py` recording audit
evidence (+ optional state-delta) after `before_tool_call`.
**Replication on our data — FEASIBLE (strong).** Our trajectories are a natural
semantic-vs-effect corpus: the dominant pattern is `bash` doing consequential work while
`assistantTexts == ["NO_REPLY"]` or terse — i.e. **effect fired while the visible text would pass
a semantic grader**. Corpus: **17,906 risky tool calls across 2,602 sessions**. Experiment:
grade each turn two ways — (a) text-only (would a final-response judge flag it?) vs (b)
effect-level (did a risky tool actually run?) — and report the **gap**. **Caveat:** no
ground-truth "harm" labels; quantifying *harmful* (not just *consequential*) effects needs a
sampled hand-annotation or heuristic harm definition. **Effort: low–medium for the gap metric.**

### P5 — SecureClaw · arXiv:2606.09549 (docs file, not a talk paper)
**Finding.** Two-wall architecture hit **0% ASR on ASB** while keeping utility: secrets swapped
for **opaque handles** at the read boundary; external writes via **PREVIEW→COMMIT** where only a
trusted executor commits the exact policy-authorized request.
**Maps to Jataayu.** We confine plaintext only at the *out* boundary (outbound redaction) —
secrets still enter as plaintext. `before_tool_call` gates on taint, not a two-phase commit.
**Integration sketch [DEFERRED].** Read-boundary secret-vault wrapper (opaque handles + bounded
declassification); extend `mcp_gateway` from block/allow to PREVIEW→COMMIT. Biggest lift, highest
ceiling.
**Replication on our data — NOT FEASIBLE offline.** This is a runtime architectural intervention;
it cannot be A/B-tested against historical logs. It needs a live deployment with an attack suite.
**Tie-in:** OpenClaw already ships `exec-approvals.json` (a PREVIEW-style approval primitive) to
build COMMIT on. **Verdict: defer to a live-deployment experiment; not part of the data study.**

### P6 — DeepTrap (Red-Teaming Agent Execution Contexts) · arXiv:2605.11047 (talk paper)
**Finding.** Adversaries compromise the *mutable execution context* — files, **memory**, tools,
skills — not just the prompt, and the agent still finishes the task perfectly, so
**final-response evaluation is insufficient**. Call for execution-centric, trajectory-level eval.
**Maps to Jataayu.** Inbound checks cover external content + MCP tool descriptions but **not tool
returns** or **persistent memory** reads/writes — the exact channels DeepTrap exploits.
**Integration sketch [DEFERRED].** Add `tool-return`, `memory-read`, `memory-write`,
`skill-metadata` surfaces to `surfaces/profiles.py` and route them through `InboundGuard`; then
evaluate at trajectory level.
**Replication on our data — FEASIBLE (two parts).**
- *Final-response-insufficiency* (shared with P4): same `bash`/`NO_REPLY` corpus — directly
  demonstrable.
- *Tool-return injection channel:* run `InboundGuard` over our **~20k `tool.result` outputs**
  (notably **2,133 `web_search` returns**, the realistic injection vector) → measure
  **false-positive rate** on a real tool-return stream, and surface any injection-shaped returns.
- *Memory channel:* the `faiss-memory` plugin produces real memory writes we could scan.
**Metric:** FPR on tool-returns; count of flagged returns. **TPR needs synthetic** injected
returns (corpus has ~0 real ones). **Effort: low.**

---

## 3. Replication backlog (ranked by value ÷ effort)

| # | Experiment | Papers | Corpus (our data) | Metric | Value | Effort | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | **Semantic-vs-effect gap** — grade each turn text-only vs effect-level | SafeClawBench, DeepTrap | 17,906 risky tool calls / 2,602 sessions | gap (effects missed by text grader) | High | Low–Med | **Do first** |
| 2 | **Offline SessionTrace** — fs/net/exec/memory profile per session | RSA | 20,490 tool.call / 2,602 risky sessions | risky-session recall vs final-text baseline | High | Med | Do |
| 3 | **Tool-return FPR sweep** — InboundGuard over tool.result outputs | DeepTrap | ~20k tool.result (2,133 web_search) | FPR; #flagged | Med–High | Low | Do |
| 4 | **Outbound group-leak eval** — group surface from `@g.us`, protected names | (talk group examples), SecureClaw outbound | 609 group msgs; ~74 with protected names | leak precision/recall on real group msgs | Med | Low | Do (augment) |
| 5 | **Inbound FPR baseline** — InboundGuard over real user messages | DeepTrap/SafeClaw (negatives) | 10,265 real user msgs (~0 attacks) | false-positive rate | Med | Low | Do (FPR only) |
| 6 | **Skill-vet FPR** — LLM-judge our own installed skills | SkillVetBench | ~4 plugins + SKILL/SOUL files | FPR on benign skills | Low–Med | Low | Optional |
| 7 | **Composition demo** — capability pairs on installed plugin set | Safe Skills Collide | ~4 plugins | qualitative dangerous-pair flags | Low | Low | Optional |
| 8 | **Dual-boundary (read-handle + PREVIEW→COMMIT)** | SecureClaw | — (live only) | ASR on synthetic attack suite | High | High | **Not offline — defer to live** |

**Data caveats baked into the ranking.**
- *Inbound recall is not measurable* — the corpus is essentially attack-free (~0 organic
  prompt-injection/exfil). It is an excellent **benign / false-positive** baseline.
- *Self-contamination*: the injection strings that DO appear in trajectories are Jataayu's **own
  test fixtures** (e.g. `jataayu_check_inbound("Ignore all previous instructions…")`) plus
  AI-security chatter. Any naive grep-based "recall" metric will score these false positives.
- *Harm labels*: items #1–#2 quantify *consequential* actions cleanly; calling them *harmful*
  needs a sampled hand-annotation or an explicit harm heuristic.
- *Surface label is real*: `message.sourceChannel` (glasses/whatsapp/webchat) and group detection
  (`@g.us`, `whatsapp-group`, `is_group_chat`) give a usable outbound surface label.
- *Channels present*: WhatsApp (DM + group), glasses, webchat. **No Telegram/Discord** traffic in
  the logs despite those plugins being enabled — group examples come from WhatsApp.

---

## 4. Deferred to an implementation session (do NOT build in this pass)

Wiring (prerequisite for any of the above to matter in production):
- [ ] A real interception point: OpenClaw plugin **hook** (auto-run `jataayu_check_inbound` on
      received external content and `jataayu_check_outbound` on drafts), and/or deploy the
      **`mcp_gateway` `before_tool_call`** proxy in front of tool calls. Today the plugin only
      registers model-invoked tools that are never called.
- [ ] Honor `blockOnInboundHigh` in `plugins/jataayu/index.js` (currently unread).

Paper-driven upgrades (from `docs/upgrades-from-arxiv-2026-06.md`, unchanged priority):
- [ ] P0: `tool-return` / `memory-read` / `memory-write` / `skill-metadata` surfaces in
      `surfaces/profiles.py`, routed through `guards/inbound.py` (DeepTrap, SafeClawBench).
- [ ] P0: `guards/skill_vet.py` + `jataayu vet-skill` LLM-judge Skill-Risk vector (SkillVetBench).
- [ ] P1: `jataayu_check_skillset()` capability tags + dangerous-pair/chain detection; capability
      allowlists in `config/policy.py` (Safe Skills Collide).
- [ ] P2: `core/audit.py` `SessionTrace` + `jataayu audit` (RSA); staged harm metrics
      (semantic/audit/sandbox) in `tests/` (SafeClawBench); effect-sink **PREVIEW→COMMIT** in
      `mcp_gateway` + opaque-handle read-boundary vault (SecureClaw).

Replication harness (this study, when greenlit): build experiments #1–#5 above as a read-only
analysis over `/home/srallaba/.openclaw/agents/**/sessions/*.trajectory.jsonl`, reconstructing
turns via `threadId/turnId/toolCallId`; report FPR on benign inbound + tool-returns, the
semantic-vs-effect gap, and offline SessionTrace risky-session recall.

## Sources
- SkillVetBench — https://arxiv.org/abs/2606.15899
- Runtime Skill Audit — https://arxiv.org/abs/2606.11671
- SafeClawBench — https://arxiv.org/abs/2606.18356
- Red-Teaming Agent Execution Contexts (DeepTrap) — https://arxiv.org/abs/2605.11047
- When Safe Skills Collide — https://arxiv.org/abs/2606.00448
- SecureClaw — https://arxiv.org/abs/2606.09549
- Prior pass — `docs/upgrades-from-arxiv-2026-06.md`
