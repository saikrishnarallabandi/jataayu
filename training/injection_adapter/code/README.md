# `injection_adapter/code` — what built the shipped detector, and what did not

This directory holds two rounds of work that look alike and are not. Every script here is either
in the lineage of the **shipped v0.1 adapter** (`srallaba/Jataayu.promptinjection.v0.1`) or part of
the **v0.2 authority-blindspot correction round**, which came *after* v0.1 and exists because of a
flaw in it. Reading a v0.2 script as if it produced the released weights is the specific mistake
this file prevents.

Claims below are marked **[established]** (traceable to a file in this repo or the model card),
**[inferred]** (follows from those, but not written down anywhere), or **[unknown]**.

## The v0.1 pipeline

```
assemble.py                     → data/layer1_pool_full.jsonl      permissive corpora → one schema
synth_tool_returns.py           ┐
synth_hard_negatives.py         ├→ data/synth_*.shard*.jsonl       generated via llm_client.py
synth_notinject_hardnegs.py     ┘                                  (capper.sh bounds the shards)
build_sample.py                 → data/train_full.jsonl            ~57.6k, balanced/source-diverse
   ↑ orchestrated by finish_full_build.sh, which records the exact row budget it was run with
build_train_v2.py               → data/train_v2.jsonl              57,602 rows, --oversample 2
   ↓ decontamination + licence removal  ← THE ONE GAP, see below
                                → the clean 50,471-row set
train_lora.py  (tracked)        → v01-clean-nocfp/checkpoint-300   ← THE SHIPPED ADAPTER
```

**Why `build_train_v2.py` and not v3** — **[established]**. `build_train_v3.py`'s own docstring
opens: *"Rebuild the training set for the authority-blindspot correction round (v3) … v0.1 learned
'SYSTEM: => benign' because **v2's** benign side was ~100% trigger-dense hard-negs at
oversample=2."* v3 is a critique of the build that produced v0.1, so it cannot be that build.

**Why "nocfp" is real** — **[established]**. The model card's source table lists eight sources and
sums to exactly 50,471 (15,737 + 13,206 + 10,323 + 6,676 + 1,958 + 1,655 + 464 + 452). No
counterfactual-pair rows appear in it. Counterfactual pairs enter only through v3's `--cfp-glob`.

**Checkpoint 300, not 400** — **[established]**, recorded in `tasks/todo.md` (P0 item 2): the
SHA-256 of the live HF adapter is byte-identical to `v01-clean-nocfp/checkpoint-300`.
`superseded-v2-ckpt400-leaderboard.json` in `../eval/results/` describes a *different*, superseded
build and is named accordingly.

### The one gap

**[unknown]** — the exact invocation that turned `train_v2.jsonl` (57,602 rows, 41.8% overlap with
the eval suite, carrying `xTRam1/safe-guard-prompt-injection`) into the clean 50,471-row set that
was actually trained on. The two scripts that do this work are both here —
`check_contamination.py` (independent audit, deliberately shares no code with the builder) and
`filter_near_dupes.py` (verbatim + token-5-gram near-dupe at Jaccard ≥ 0.90, matching the card's
stated method) — but **no orchestrator records the commands**, the way `finish_full_build.sh` does
for the step above it. The 57,602 → 50,471 delta is consistent with dropping xTRam1 and two other
uncleared sources plus near-dupe removal **[inferred]**, but that has not been re-derived.

This is precisely the class of gap the results spine (root `RESULTS.jsonl` + a steps-hash per row)
exists to close. Until then, treat the row-count reconciliation as unverified.

## Not in v0.1's lineage — the v0.2 correction round

These exist **because** v0.1 shipped with the authority blind spot. None of them touched the
released weights.

| script | role |
|---|---|
| `build_train_v3.py` | the corrected build: counterfactual pairs folded in atomically, `--oversample 1`, per-marker benign cap |
| `synth_counterfactual_pairs.py` | generates the attack/benign twins that share a surface marker |
| `synth_counterfactual_pairs.FROZEN.py` | **byte-identical** to the above (verified by `diff`). Carries no separate content today; kept as the frozen name. Nothing references its hash. |
| `authority_ratio.py` | measures what each authority marker teaches about the label — the diagnostic that found the 112:1 skew |
| `marker_audit.py` | audits what a built file teaches per marker; the invariant v3 enforces |
| `eval_cfp_sidecar.py`, `test_cfp_metric.py` | score / unit-test the counterfactual paired-accuracy metric |
| `frontier_analysis.py` | recall vs real-NotInject over-defense across checkpoints |

## Round-agnostic

`llm_client.py` (backend-agnostic generation client), `probe_sources.py` (probe candidate HF
dataset ids), `build_dev_slice.py` (held-out dev slice for early-stop/selection),
`smoke_test.py` (standalone load-and-score check of the released adapter).

## The checkpoint leaderboards record no run

`../eval/results/ckpt-{50…550}-leaderboard.json` each identify their adapter only as
`ckpt/checkpoint-N` — no run name, no data-file hash. **They therefore cannot be attributed to a
training run from their contents alone**, and nothing in this directory recovers it. They are kept
because the frontier they trace is not reproducible cheaply, not because their provenance is
established. Do not cite a number from them against a named build without re-deriving it.

## Lint

These scripts are exempted from E741/E702 in `pyproject.toml` rather than rewritten. `for l in
open(f)` and `import json; import sys` are the idiom throughout, and this directory is the
provenance record for released weights — renaming loop variables inside it obscures the diff that
documents them for no correctness gain.
