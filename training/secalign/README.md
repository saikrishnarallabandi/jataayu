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
# real run — dgx-pavan (GB10) or a vast.ai RTX 4090:
python train_dpo.py --config config.yaml  # logs to wandb, saves to exp/secalign-qwen3-8b
```
Recommended: vast.ai RTX 4090 (~$0.30/hr) or dgx-pavan. QLoRA keeps an 8B in ~16GB. Destroy the
vast instance when done.

## Evaluate
After training, point the slow path at the tuned model and re-run the benchmark:
```bash
JATAAYU_LLM_BACKEND=ollama JATAAYU_LLM_MODEL=secalign-qwen3-8b \
  python ../../eval/run_slowpath_bench.py --host http://localhost:11434 --model secalign-qwen3-8b
```
Target: recall up from the current slow-path ~0.50 toward SecAlign's <10% ASR, at lower latency
than the 35B judge.
