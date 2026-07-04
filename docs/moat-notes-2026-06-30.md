# Jataayu moat notes — 2026-06-30

Context: AIEWF / SentinelForge business-model discussion.

Jataayu's moat is not "better regex." A pattern catalog is useful but weakly defensible.
The defensible path is operational context: provenance-aware action boundaries, surface-aware
policy, bidirectional guarding, release-gate distribution, and a real trace corpus.

## Moat stack

1. **Action-boundary design**
   Most guardrails inspect text. Jataayu should inspect whether untrusted text is about to drive
   shell, network, secret read, file write, code eval, or memory write. That is closer to where
   real agent harm happens.

2. **Surface-aware policy**
   GitHub issues, PR comments, web pages, email, internal coding tasks, and group chats should not
   share a trust level. Jataayu already models surfaces; keep making this a first-class product
   primitive rather than generic content moderation.

3. **Bidirectional guard**
   Buyers care about both sides:
   - inbound: can users or untrusted content attack the agent?
   - outbound: can the agent leak secrets, credentials, private context, or sensitive report data?

4. **Taint/provenance layer**
   Tracking untrusted data as it flows into tools and actions is harder to copy than a pattern
   list. This becomes a real moat if it is robust, observable, and easy to integrate.

5. **Benchmark plus failure honesty**
   The credible story is that no detector is complete. Regex is high precision / low recall;
   slow paths improve recall; action-boundary defenses reduce harm even when detection misses.
   That honesty is stronger than vendor-style overclaiming.

6. **Distribution wedge through release gates**
   Bundled into SentinelForge, Jataayu can sit in CI and trace workflows. Once it becomes part of
   the release path, replacement friction rises.

## Defensibility ranking

- Weak moat: pattern catalog.
- Medium moat: local/private deployment.
- Strong moat: provenance + action-boundary + CI release-gate integration + real trace corpus.

## SentinelForge thesis

Jataayu alone is defensible-ish. Jataayu plus SentinelForge's reliability/security trace corpus is
the stronger moat.

Every audit should improve:
- agent failure and injection trace corpus
- leak and credential examples
- policy defaults by surface
- LoRA labels for local SLM judges
- release-gate templates
- evidence reports for buyers

## Product implication

Do not position Jataayu as a standalone prompt-injection detector first. Position it as the trust
perimeter inside private/local agent release gates:

- secure trace intake
- prompt-injection and tool/action risk checks
- outbound secret/privacy checks
- plugin/skill/tool composition risk audit
- CI gates that fail on reliability plus security regressions

