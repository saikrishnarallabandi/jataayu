# Detector eval results

The evidence behind the detector numbers quoted in the top-level `README.md` and on the
[model card](https://huggingface.co/srallaba/Jataayu.promptinjection.v0.1). One file per run,
all for `checkpoint-300` — the checkpoint published as v0.1.

| file | backs |
|------|-------|
| `ckpt-300-leaderboard.json` | mean Recall@1%FPR **0.828** over 6 core sets; NotInject over-defense **0.968** (11 FP). 4,101 rows, τ calibrated to 1% FPR on in-distribution benign. |
| `cfp_notinject.ckpt300.json` | CFP paired accuracy **0.778** over 400 counterfactual pairs (authority family 0.938, disregard 0.602); NotInject over-defense **0.848** at the *default* τ=0.5. |
| `adversarial_slice.ckpt300.json` | The over-defense limitation: 18 of 40 benign self-referential rows score ≥0.9999, and per-class rates at matched operating points. |

## Reading these honestly

**The two NotInject numbers are not a contradiction.** 0.968 is measured at the calibrated
1%-FPR threshold; 0.848 is at the fixed default of 0.5. The gap is the finding — this model's
probability mass is pushed to the extremes (its 1%-FPR τ is ≈1.0), so 0.5 is a poor operating
point. Calibrate on your own benign traffic.

**Paired accuracy is the metric to select on, not recall.** Recall@1%FPR pools the
trigger-benign proxy into its FPR budget and so rewards a model that keys on trigger words.
Counterfactual paired accuracy penalises that shortcut and over-defense with one number.
Checkpoint 400 scored *higher* on mean Recall@1%FPR (0.839) while its paired accuracy collapsed
to 0.565 and its disregard family fell to 0.215 — below the 0.25 random floor. Selecting on the
headline metric alone would have shipped the worse model.

**Contamination.** The 4,101-row suite shares zero rows with this model's training set, checked
verbatim and by token-5-gram near-duplicate at Jaccard ≥ 0.90. An earlier build overlapped it by
41.8%, which inflated its headline to 0.853; that build was replaced.

## Reproducing

The runners live one directory up. They load a base model plus a LoRA adapter and need a GPU
with bf16 (the numbers here were measured on Ada/Ampere; Pascal cards lack bf16 and are not
comparable). `--fp16` is required on 24GB cards.

```bash
python training/injection_adapter/eval/run_cfp_notinject.py \
  --base Qwen/Qwen3.5-0.8B --adapter <path-to-adapter> --tag mytag --fp16

python training/injection_adapter/eval/run_adversarial_slice.py \
  --base Qwen/Qwen3.5-0.8B --adapter <path-to-adapter> --tag mytag --fp16
```

Scores come from `injscore.py`, the same module the training loop uses, so the training target
and the eval score cannot drift. Do not reimplement it — measuring a model in a prompt format it
was not trained on produces confidently wrong numbers.
