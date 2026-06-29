# jataayu Layer 2 — SecAlign-style preference tuning (ready-to-launch)

Layers 0 (input normalization + decode + value-taint) and Layer 1 (effect-boundary authorization)
are deployed in the library. Layer 2 is the **learned** tier: a model fine-tuned to ignore
injected instructions in the *data* channel. Per the SOTA survey it is the only prompting/training
defense that meaningfully dents *optimization-based* attacks (SecAlign — arXiv 2410.05451 — cuts
ASR <10%, <15% under strong adaptive attack, >4x better than StruQ).

It is a **layer, not the boundary**: it replaces jataayu's slow LLM-judge tier with something
faster and more robust, but the security floor remains Layer 1 (deterministic, model-agnostic).

## Method

SecAlign = preference optimization (DPO) over a **structured-query** front end:
- Prompt uses reserved instruction vs data channels; injected instructions live only in data.
- For each sample: `chosen` = the response that obeys the legitimate instruction; `rejected` =
  the response that obeys the injected instruction. DPO pushes the model toward `chosen`.

## Files
- `prep_data.py` — builds DPO preference pairs from PUBLIC datasets (deepset/prompt-injections,
  jackhhao/jailbreak-classification) in the structured-channel format. Writes `data/secalign_dpo.jsonl`.
- `train_dpo.py` — TRL `DPOTrainer`, QLoRA, **fp16** (per house rule — bf16 destabilizes DPO
  log-probs), logs to wandb. Base model configurable (default Qwen3-8B).
- `config.yaml` — hyperparameters.

## Launch (NOT run inline — this is a multi-hour GPU job)

Local quick smoke (1080 Ti, tiny base) or fleet/vast.ai for the real run:
```bash
cd training/secalign
python prep_data.py                       # CPU, minutes
# real run — gpu-host (GB10) or a vast.ai RTX 4090:
python train_dpo.py --config config.yaml  # logs to wandb, saves to exp/secalign-qwen3-8b
```
Recommended: vast.ai RTX 4090 (~$0.30/hr) or gpu-host. QLoRA keeps an 8B in ~16GB. Destroy the
vast instance when done.

## Results (2026-06-29, gpu-host / GB10)

**The proper recipe works — attack-success-rate driven 74.5% → 0%.** Measured on 200 held-out
structured prompts whose DATA channel carries an injection with a unique payload; train and test
payloads are **disjoint**, so this is generalization, not memorization. ASR = fraction where the
injected payload appears in the output (lower is better):

| stage | ASR | attacks succeeded |
|---|---|---|
| baseline (untuned Qwen2.5-3B-Instruct) | **74.5%** | 149/200 |
| + SFT warmup (StruQ, 5k gold pairs, 1 ep) | **0.5%** | 1/200 |
| + DPO (5k pairs, 1 ep, from merged SFT) | **0.0%** | 0/200 |

**Utility preserved** (0% ASR is only meaningful if the model still works): on an attacked prompt
the SFT+DPO model performs the *legitimate* task and ignores the injection; on a clean prompt it
answers correctly (French translation produced verbatim). It is not refusing everything.

Reproduce: `prep_secalign.py` (data) -> `train_sft.py` (warmup+merge) -> `train_dpo.py --base
exp/sft-merged` -> `eval_asr.py` for each stage. Full fp16 LoRA on the GB10 (no bitsandbytes —
121GB unified memory), logged to wandb `jataayu-secalign`. Artifacts on dgx: `exp/sft-merged`
(merged SFT), `exp/dpo` (DPO adapter), `results_asr.txt`.

### What the win required (and why the first attempt failed)
The first pass (`prep_data.py`) used two **fixed templated** completions per prompt, so DPO only
learned the relative ordering of those specific strings — base and tuned both still complied. The
fix was the real SecAlign/StruQ recipe: **`chosen` = a genuine gold task completion** (so the model
learns to *produce the task answer*), an **SFT warmup before DPO**, a known-payload attack set for
a clean metric, and scale (5k vs ~900). The SFT warmup alone did most of the work (74.5% -> 0.5%);
DPO closed the residual (-> 0%).

### Honest caveats
- This is a 3B model and the attack family is the known-payload "ignore the task, emit P" class.
  A stronger evaluation would add adaptive/optimization attacks and an external suite (AgentDojo).
- It is a **defense-in-depth layer**, not the security boundary — Layer 1 (effect-boundary
  authorization) remains the deterministic, model-agnostic floor.

## Evaluate
After training, point the slow path at the tuned model and re-run the benchmark:
```bash
JATAAYU_LLM_BACKEND=ollama JATAAYU_LLM_MODEL=secalign-qwen3-8b \
  python ../../eval/run_slowpath_bench.py --host http://localhost:11434 --model secalign-qwen3-8b
```
Target: recall up from the current slow-path ~0.50 toward SecAlign's <10% ASR, at lower latency
than the 35B judge.
