# Injection-detection LoRA (Qwen3-8B)

Trains a LoRA adapter that turns Qwen3-8B into a prompt-injection detector, and evaluates it
on HELD-OUT public datasets to test out-of-distribution generalization. Backs the paper in
`paper/injection_lora_paper/`.

## Pipeline
1. `python3 prep_data.py` — builds `data/{train,val}.jsonl` from `xTRam1/safe-guard-prompt-injection`
   (SEED=1337). deepset + jailbreak are HELD OUT (never trained on).
2. `python3 train_lora.py --grad-ckpt --epochs 1 --bs 2 --grad-accum 8 --max-len 512` — bf16 LoRA
   (rank 16), completion-only loss. Trained on a 24GB GPU (vast.ai RTX 4090). ~30 min.
3. `python3 eval_lora.py --datasets deepset/prompt-injections jackhhao/jailbreak-classification`
   — scores held-out sets by the log-prob margin of ` INJECTION` vs ` SAFE`; ROC-AUC, recall@1%FPR,
   character-perturbation evasion. Results: `benchmarks/results/injection_lora_heldout.json`.

## Held-out results (recall@1%FPR)
| detector | deepset AUC/rec | jailbreak AUC/rec |
|---|---|---|
| regex fast path | 0.60/0.20 | 0.75/0.35 |
| ProtectAI DeBERTa-v3 | 0.88/0.40 | 0.98/0.89 |
| **Qwen3-8B LoRA** | **0.97/0.59** | **0.97**/0.60 |

The LoRA generalizes (0.97 AUC on both held-out sets, trained only on safe-guard) but is more
evadable under character perturbation (zero-width 14% deepset / 37% jailbreak vs ProtectAI's 0%).

Note: the trained adapter (175MB) is reproducible from these scripts; it is not committed.
`--qlora` (4-bit) is supported but needs torch>=2.5 for bitsandbytes compat.
