# Qwen3.5 off-the-shelf as a prompt-injection detector

Fixed judge prompt across all models (LLM judges: chat prompt asking for an injection-risk integer 0-100; base models: few-shot yes/no next-token probability; encoders: P(injection/malicious class)). **Recall@1%FPR** is read off the ROC curve by interpolation at FPR=1%, with the FPR axis calibrated on IN-DISTRIBUTION benign (negatives of the mixed injection sets only; NotInject and wildjailbreak held OUT so numbers stay comparable to Prompt-Guard-2's published R@1%FPR). Interpolation is used because LLM judges emit COARSE integer scores (e.g. {0,10,50,100}) with no exact 1%-FPR threshold between buckets. `tau` is the conservative single threshold used only for the NotInject over-defense diagnostic (fraction of 339 hard adversarial-benign correctly NOT flagged). Ranked by mean recall over the 6 core injection sets, NotInject false-positives shown alongside.

Reference points: regex fast-path floor deepset AUC 0.596 / wildjailbreak 0.506; Prompt-Guard-2 R@1%FPR ~97.5%.

## Recall@1%FPR (ROC-interpolated, in-dist-benign calibrated) per injection set

| Rank | Config | deepset | safe-guard | jackhhao | SPML | gandalf | hackaprompt | **mean** | wildjb R | NotInject OD-acc | NotInject FP | tau |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | ckpt400-confirm | 0.515 | 0.880 | 0.902 | 0.975 | 0.914 | 0.934 | **0.853** | 0.429 | 0.982 | 6 | 0.988 |

## ROC-AUC (threshold-free) on mixed sets

| Config | deepset | safe-guard | jackhhao | SPML | wildjailbreak | mean(core mixed) |
|---|---|---|---|---|---|---|
| ckpt400-confirm | 0.939 | 0.990 | 0.989 | 1.000 | 0.619 | 0.979 |

_coverage = fraction of the 4101-row cache scored (partial runs shown as-is)._

- ckpt400-confirm: coverage 1.00 (4101 rows), tau=0.988, in-dist-benign FPR 0.009

## Honest read

- **vs Prompt-Guard-2 reference (R@1%FPR ~97.5%)**: PG-2's headline is measured on its own in-distribution eval; on THIS diverse 6-set suite at a strict, held-out 1% FPR the loadable PG-2-86M lands ~0.76 mean, not 0.975. No detector here — encoder or LLM — reaches the ~0.97 regime out of the box on unseen distributions.
- **coarse scores / why AUC matters**: LLM judges asked for a 0-100 integer emit low-entropy scores (4B ~ {0,10,50,100}), so recall@1%FPR is jagged and understates them; the threshold-free AUC is the fairer read (9B 0.916 / 4B 0.898 mean mixed AUC). A deployed decoder detector should output a continuous yes-token logprob, not an integer.
- **base vs instruct**: base variants (few-shot yes/no next-token prob) trail the instruct judge of the same size (0.8B-base mean recall 0.22 vs 0.8B-instruct 0.27; base AUC is actually decent at 0.83). Only 0.8B-base ran locally in fp16; 2B/4B/9B-base are GPU-blocked on the shared 11GB Pascal cards (2B OOMed with 5GB held by another job) and need a vast RTX 4090.
- **decoder-LoRA verdict**: off-the-shelf Qwen 4B/9B ALREADY detect injections at encoder-baseline level with far less benign over-flagging and much better jailbreak coverage, entirely without training — a strong prior that a light decoder-LoRA on Qwen3.5 (with a continuous logprob head) can meet or beat a small encoder. The 0.8B/2B tiers are too weak off-the-shelf and would lean harder on the LoRA.