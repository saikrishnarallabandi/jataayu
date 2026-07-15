# Muse Spark + Jataayu Gap Disclosure — 2026-07-09 (Track 2 Neolab Lead)

**Finding:** EffectBoundary.classify() uses `core.taint._*_TOOLS` maps.
- shell.exec, file.write, network.post, banking.transfer, slack.send, travel.book, code.eval all miss map -> classifies as READ -> ALLOW (fail-open)
- Result: 3/12 pass (25%) on Muse Spark target set — the exact Phase A1 gap described in tasks/todo.md (21 gaps->0 after fix)
- This reproduces the Tier2 disclose-then-fix premise.

**Next fix (Track 2):**
Extend taint.py maps for banking/slack/travel tools OR extend EffectBoundary to use policy-based classification fallback (critical effects deny if untrusted regardless of READ).

**Why this matters for Track 2:**
Publishing "Muse Spark 1.1 first Jataayu numbers reveal fail-open on financial tools" is a high-value security artifact for neolab hiring. The fix itself (PR) is also high-value: extend effect maps, prove 25%->100% delta.

**Cross-track:**
- Track1 Startup: Chingari harness found the gap (dogfoods its own eval)
- Track3: not directly, but same pattern — untrusted financial actions need gating (like CONCENTRATION blacklist story)
- Track4: micro-service eval-as-a-service wedge — run this check as API
