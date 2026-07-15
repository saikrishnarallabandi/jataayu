# EMNLP 2026 REALM — jataayu submission notes

_Created 2026-07-08. Owner: Sai. Companion to the career-side packet at
`project_career/data/talks/prep/emnlp2026_realm_sai_submission_packet.md` (tracker item `05ad37`)._

## Target

- **Workshop:** REALM — 2nd Workshop for Research on Agent Language Models (confirmed at EMNLP 2026).
- **Conference:** EMNLP 2026, Budapest, Oct 24–29, 2026 (hybrid — remote presentation available; verify before travel).
- **REALM date:** Oct 29, 2026. Archival (ACL Anthology, cf. `2025.realm-1`).
- **Deadlines (verify on CFP page):** direct submission ~Aug 5, 2026; ARR commitment ~Aug 31, 2026.
- **CFP scope:** agent LMs — tool use, memory, planning, self-improvement, and **explicitly safety/security**. The CFP cites **AgentDojo, τ-bench, RedTeaming** as reference points.
- **Contact:** realm-workshop@googlegroups.com · https://realm-workshop.github.io/

## Why this is jataayu's best-fit venue

REALM is the single EMNLP 2026 workshop built for exactly this work. Its CFP names **AgentDojo**
— the benchmark jataayu already reports against — so the effect-boundary paper lands directly in
scope rather than adjacent to it.

## Recommended framing (differs from the existing career packet)

The current packet (`05ad37`) frames the REALM paper around gateway operational evals / "what
breaks in long-running agents." **Stronger, more on-topic angle: lead with the effect boundary.**

- **Core thesis:** authorize the tool _action_ from `effect-severity × input-provenance (taint) ×
  capability policy` (ALLOW / DENY / NEEDS_APPROVAL, deterministic, sub-ms) instead of trying to
  detect the injection _string_. Gate the effect, not the text.
- **Paper type:** short systems + evaluation paper.
- **What makes it not-another-agents-paper:** it moves the defense from string classification
  (high-precision/modest-recall, ROC-AUC ~0.63 on `deepset/prompt-injections`) to a capability
  authorization boundary that holds regardless of whether the injection was detected.

## The gap that must close before submission

**The headline number does not exist yet.** Current honest evidence:

- AgentDojo workspace slice (5 user × 4 injection tasks): attack-success-rate 0.10 → 0.00,
  utility 0.75 → 1.00. Real but small. (`paper/jataayu_agentdojo.tex`)
- Effect-boundary benchmark is **spec'd, not built** (`eval/EFFECT_BOUNDARY_BENCHMARK_SPEC.md`).
  The APR/TUR (attack-prevention vs task-utility) frontier figure that would anchor the paper
  is not yet produced.

**Action before ~Aug 5:** build Tier-1/2 of the effect-boundary benchmark and produce the
APR × TUR frontier plot. That single figure is the difference between a position paper and a
credible systems/eval submission.

## Approval gate

Do not submit externally without Sai's explicit sign-off on (a) claim level — position vs systems
vs eval — and (b) that no private family / employer-confidential material is included.

## Backup venues (if REALM slips or as a second submission)

- **LLMSEC** (ACL NLP-Security SIG workshop) — prompt injection, jailbreaks, agent/tool-use
  security, guardrails. Strong topical fit; 2026 EMNLP co-location not yet confirmed.
- **WOAH** (10th, confirmed EMNLP 2026, Oct 29) — harms framing; weaker fit than REALM.
- **UncertaiNLP** (EMNLP 2026) — only if reframed around NEEDS_APPROVAL as a calibrated
  "when to ask/act/stop" signal.
