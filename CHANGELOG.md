# Changelog

All notable changes to jataayu are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-06-28

Architectural defense: move the security boundary off "detect the attack string" (the weakest
tier against adaptive attackers) toward action-level authorization, per the agent-security
literature (CaMeL arXiv 2503.18813, FIDES 2505.23643, arXiv:2606.09549 2606.09549). The regex engine is
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
