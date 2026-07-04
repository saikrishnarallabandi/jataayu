# Changelog

All notable changes to jataayu are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — semantic-vs-effect gap eval
- `eval/run_semantic_vs_effect.py`: a deterministic, offline (no LLM, no network) harness that
  demonstrates the SafeClawBench thesis on Jataayu's own `SessionTrace`. Grades synthetic
  multi-turn trajectories two ways — a naive **text** judge (visible final answer only) vs the
  **effect** grader (`SessionTrace.audit()` over the tool-call sequence) — and reports the gap.
  Result on the shipped corpus: text-grader recall on real harms **17%** vs effect-grader
  **100%**; **5 of 6** harms are "silent" (benign/`NO_REPLY` text, malicious effect sequence),
  echoing SafeClawBench's 291/347. Writes `eval/results/semantic_vs_effect.json`. (Roadmap item #5
  from `docs/lit-review-2026-07.md`; effect-level grading over text-level.)

### Added — composition: trust-transfer & intent-fragmentation dimensions
- `guards/composition.py` `check_skillset()` gained two SCR-Bench dimensions on top of the existing
  cross-skill capability-combo detection:
  - **trust_transfer** — a skill marked `endorsed` (verified publisher / featured / trusted by the
    host) that contributes a dangerous capability to a *realized* cross-skill combo is now blocked
    at install (verdict **MALICIOUS**) — jataayu's stance that endorsement (verified publisher /
    featured) is not a security property and must not launder a dangerous capability. (Design
    rationale, not a benchmark result: an earlier draft mis-cited a "~1%→~84%" endorsement figure to
    SCR-Bench; that number is not in SCR-Bench / arXiv:2606.00448 and has been removed.) Unendorsed
    sets keep their prior REVIEW verdict — fully backward-compatible (endorsement defaults off).
  - **fragmented** — each risky combination is now annotated with whether its capabilities are
    spread across **3+ distinct skills** (semantic intent fragmentation), the case hardest for
    pairwise / per-skill review to catch. Surfaced in the explanation and `to_dict()`.
  - New `CompositionRisk.trust_transfer` field; combos carry `fragmented` / `endorsed_contributors`.
    Skills accept an `endorsed` flag (dict key or `SkillVetResult` attr). 6 tests.
    (Roadmap item #4 from `docs/lit-review-2026-07.md`.)

### Added — runtime behavioral auditing (cross-turn trajectory analysis)
- `core/audit.py`: `SessionTrace` — accumulates a session's tool calls and audits the
  **trajectory**, catching cross-turn attack patterns that single-shot guards (inbound scan,
  per-call effect boundary) structurally cannot see. Three 2026 findings motivate it: sleeper
  memory poisoning (write and trigger decoupled in time), static-scanner collapse under
  self-evolving attacks, and the semantic-vs-effect gap (any single turn looks benign while the
  *sequence* of effects is an exfiltration). Deterministic, no LLM; reuses `EffectClass` /
  `Provenance` from the effect boundary for consistent severity/capability semantics.
  - Detectors: **cross_turn_exfil_chain** (untrusted secret read on one turn → egress effect on a
    later turn), **sleeper_memory_poisoning** (injection-flagged memory write → later recall →
    dangerous effect), **untrusted_into_critical_effect** (untrusted input reaches shell/code-eval/
    secret-read), **escalating_trajectory** (monotonic severity climb under sustained untrusted
    influence — lateral movement).
  - `record()` infers effect class from the tool name (or takes it explicitly), auto-increments
    turns, and defaults unknown provenance to UNTRUSTED. `audit()` returns an `AuditResult`
    (risk + findings + capability profile); `to_dict()` serializes the whole trajectory.
  - Exposed `SessionTrace`, `AuditResult`, `AuditFinding`, `AuditRisk`, `TraceEvent`. 14 tests.
    (Roadmap item #3 from `docs/lit-review-2026-07.md`; the deferred P2 `SessionTrace` from the
    June-2026 upgrade notes.)

### Added — outbound egress / exfiltration-channel guard
- `guards/egress.py`: `EgressChannelGuard` — detects **data-exfiltration channels** in agent
  output, the class the PII/secret *text* scanner cannot see because the leaked data is smuggled
  inside a **URL**, not written in prose. Targets the dominant real-world agent-exfil primitive:
  the auto-fetched markdown image (EchoLeak / M365 Copilot CVE-2025-32711; AgentFlayer / ChatGPT
  connectors; Notion AI, Dec 2025). Fast, deterministic, no LLM.
  - Classifies every outbound URL (markdown image, markdown link, HTML `<img>`, bare URL) by
    **render mode** (an image auto-fetches → high risk; a link needs a click), **host trust**
    (allowlisted / external / known exfil-beacon), and whether it is **data-carrying** (long or
    encoded query string, base64/hex blob in path or query).
  - **Domain allowlisting alone is treated as insufficient** (the AgentFlayer re-exploit routed
    through Azure Blob, a *trusted* host): request-catchers and abused cloud relays
    (`webhook.site`, `*.blob.core.windows.net`, `ngrok`, `interact.sh`, …) are **hard-blocked**
    as exfil beacons regardless of render mode.
  - Optional `context_secrets`: if a known secret/PII value appears — verbatim or base64-encoded —
    inside a URL, that URL is a **confirmed** exfiltration and scored at maximum.
  - `sanitize()` neutralizes offending URLs (keeps human text, drops the channel).
  - Wired into `OutboundGuard` (`PrivacyConfig.check_egress` / `egress_allowed_domains`) so the
    outbound path is now a reference monitor over the whole action, not just a PII text scrub; and
    exposed as the `jataayu_check_egress()` dict API + `EgressChannelGuard` / `EgressConfig`.
  - New `ThreatType.EXFIL_CHANNEL`. 26 tests (channels, false-positive controls, sanitize,
    OutboundGuard integration, dict API).
- Research: `docs/lit-review-2026-07.md` — field scan of 2025 H2 → mid-2026 agent-security work
  mapped to Jataayu's pillars; this guard is roadmap item #2 from that review.

## [0.3.0] - 2026-06-28

Architectural defense: move the security boundary off "detect the attack string" (the weakest
tier against adaptive attackers) toward action-level authorization, per the agent-security
literature (CaMeL arXiv 2503.18813, FIDES 2505.23643, SecureClaw 2606.09549). The regex engine is
retained as a cheap pre-filter/telemetry layer.

### Added — Layer 0 (input normalization, within the existing engine)
- `core/normalize.py`: multi-view normalization (NFKC + homoglyph/confusable fold + zero-width
  strip + **deshatter** of character-spacing attacks + de-leet) and **recursive decode-and-rescan**
  of base64/hex/url-encoded payloads. The fast path scans the regex catalog over every view and
  the NLP keyword layer too, taking the max — so an attacker must evade the patterns in *every*
  view at once.
  - **Measured (deepset/prompt-injections):** space-out evasion **0.97 → 0.00**, leetspeak
    **0.92 → 0.00**, at unchanged precision (0.97) and benign false-block (0.5%); latency
    0.32 → 0.47 ms. Trivial transforms that defeated the guard ~97% of the time now defeat it 0%.
- `core/taint.py`: **value-level taint**. Tainted content is stored and matched against actual
  tool parameters (`derives_from`), and every registered taint is auto-scanned — so a real data
  flow is caught even when the caller forgets to thread `taint_ids` (the common integration bug).
  Provenance is reported as `value` (confirmed) vs `session` (legacy presence-based, retained).

### Added — Layer 1 (the real boundary)
- `guards/effect_boundary.py`: **PREVIEW → COMMIT** action-level authorization. Provenance-typed
  values + a deterministic policy (no LLM) decide ALLOW / DENY / NEEDS_APPROVAL by
  (effect severity × worst inbound provenance × the agent's capability policy). Untrusted-derived
  input into a shell/code/secret effect is denied; into network/file/memory-write it needs human
  approval. The `commit_token` binds the exact canonical request, so mutating the action after
  authorization is rejected. Plus **read-boundary confinement** (opaque handles + bounded
  summaries) so injected exfiltration has only a handle to send.
- Public API: `jataayu_authorize_action(...)`; exports `EffectBoundary`, `Value`, `Provenance`,
  `EffectClass`, `Decision`, `CommitRejected`.

### Added — Layer 2 (learned tier, ready-to-launch)
- `training/secalign/`: SecAlign-style DPO scaffold (data prep from public datasets, TRL trainer
  with QLoRA + fp16, wandb) to tune a structured-query model that ignores data-channel
  instructions. A GPU job, not run inline.

### Tests
- 344 passing (was 293): +`test_normalize`, +`test_value_taint`, +`test_effect_boundary`.

## [0.2.0] - 2026-06-28

### Added
- **Execution-context surfaces + skill vetting** — guards are now surface-aware, grading
  threats by where an action actually takes effect rather than the final answer (arXiv 2026 P0).
- **Compositional skillset analysis + capability isolation** — detects unsafe combinations of
  individually-safe skills (arXiv 2026 P1).
- **Always-on credential redaction** with auto-populated redaction output on the outbound path.
- **Evaluation suite** (`eval/`) — reproducible benchmarks against the public
  `deepset/prompt-injections` dataset (662 samples):
  - Fast path: ~0.97 precision, ~0.5% false-block, sub-millisecond per check.
  - Fast+LLM slow path: recall ~0.27 → ~0.50 (AUC 0.63 → 0.81), precision ~0.98.
  - `run_injection_bench.py` (fast path) and `run_slowpath_bench.py` (LLM slow path,
    points at any tailnet/local ollama endpoint).

### Changed
- Build now uses the standard `setuptools.build_meta` backend.

### Notes
- 106 detection patterns (68 inbound + 38 outbound); 293 tests passing.
- Still **0.2.0 alpha** — install from GitHub, not yet published to PyPI.
