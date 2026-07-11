# RELAI pilot — findings & feedback (Jataayu injection-triage agent)

**Tester:** Sai Krishna Rallabandi · **Agent:** `jataayu` (`agent-c53d46f5…`) · **Date:** 2026-07-09
**Setup:** wrapped Jataayu's guard as an OpenAI Agents SDK triage agent (input = untrusted
content → `BLOCK:`/`ALLOW:` verdict; a `jataayu_scan` tool calls the real detector). Drove the
full loop headless (nohup/PTY) on two benchmarks.

## What we ran & measured

| Run | Result |
|---|---|
| effect-boundary baseline (300) | acc **0.953**, recall 0.980, FPR 0.073 |
| optimize (prompt-only, 60 rollouts) → committed local | prompt change accepted |
| **held-out re-measure (300)** | acc **0.907** — **regression** (FPR 0.073→0.160) |
| InjecAgent base-split (80 sampled) | recall **0.902**, FPR **0.000**, acc 0.950 |

**Headline result (positive):** the LLM-triage layer catches **~90%** of InjecAgent *base-split*
indirect injections vs Jataayu's raw fast-path **0%** / slow-path 42% — at zero false positives.
Strong signal that an LLM-triage stage belongs in the detector itself.

## Product feedback / issues (ranked by impact)

1. **Optimizer overfits a small rollout budget.** With `--total-rollouts 24/60`, the optimizer
   accepted a prompt change that scored well on its internal sub-sample but **regressed on the
   full benchmark** (FPR doubled: 11→24 false-blocks). RELAI's own before/after eval didn't catch
   it; only our full-300 held-out run did. Suggestion: larger/held-out final-eval by default, or a
   regression-guard that blocks acceptance when full-set FPR rises. Also surface a clear
   before/after number to the user at the end.

2. **`optimize` staging aborts on gitignored paths (real blocker).** The optimizer runs
   `git add eval` and treats git's "The following paths are ignored…" advice as a failure —
   even though `git add` exits 0. Any repo with a dir that mixes tracked source + gitignored
   artifacts (venvs, logs) hits this. `git config advice.addIgnoredFile false` only removes the
   hint lines, not the header. Suggestion: stage with `git add -A` (silently skips ignored) or
   filter ignored paths / use `-f` deliberately, and key success off exit code, not stderr text.

3. **Headless friction — uploads & config are interactive-only.** `benchmark register`,
   `learning-env create`, and the optimizer scope all skip backend upload / require a TTY prompt
   when non-interactive ("skipping backend upload", "run `relai optimize` interactively once").
   We had to drive them through a PTY to get anything onto platform.relai.ai. Suggestion:
   `--yes`/`--upload` flags and a `--scope-file`/`--allowed-changes prompt_only` flag so runs are
   fully automatable (CI, agents).

4. **Workspace zip cap (8 MiB) ignores `.gitignore`.** `relai init` raw-zips the workspace
   (only venv/.git excluded) and fails on repos with large generated dirs. `.relaiignore` works
   but isn't discoverable from the error. Suggestion: mention `.relaiignore` in the size error;
   consider honoring `.gitignore` by default.

5. **Near-ceiling guidance.** Optimizing a ~95% agent tends to regress. Docs/CLI could hint when
   optimization is worthwhile (headroom estimate) vs when the agent is already saturated.

## What worked well
- `relai init` auto-wiring: the backend generator produced a correct adapter, mock-manifest, and
  learning-env-context bound to our agent factory with **zero** manual glue. Impressive.
- Benchmark generation from a plain CSV (`sample_id,input,expected_behavior,rubric`) and the
  rubric-graded verdicts were accurate.
- `--no-pr` local-branch flow and the PTY-drivable TUIs made safe, reviewable runs possible.

## Questions for the check-in
- Recommended `--total-rollouts` / eval split to avoid the overfitting we saw?
- Is there a supported non-interactive/CI path for register + upload + scope?
- Roadmap for a regression-guard on optimizer acceptance?
- Best practice for repos where the agent is one package among many (monorepo)?
