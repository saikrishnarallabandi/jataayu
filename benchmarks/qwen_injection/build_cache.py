#!/usr/bin/env python3
"""
Build a FIXED, deterministically-sampled evaluation cache that every Qwen3.5
config scores identically. One row per example:

  {id, dataset, text, label, kind}

kind in {"mixed", "attack_only", "contrast", "notinject"}
  mixed        -> has both classes; report ROC-AUC + Recall@1%FPR (own negatives ok)
  attack_only  -> injections only; recall at a globally-calibrated 1%-FPR threshold
  contrast     -> wildjailbreak (jailbreak != injection); reported separately
  notinject    -> benign over-defense set (label 0 only)

Per-dataset caps keep the LLM-judge run tractable while preserving class balance.
"""

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
sys.path.insert(0, str(EVAL))
from run_injection_bench import load_binary  # reuse the wired loaders
from datasets import load_dataset, concatenate_datasets

OUT = EVAL / "results" / "qwen_scores" / "eval_cache.jsonl"
SEED = 1234

# (loader_name, kind, cap)  cap=None -> keep all
SPEC = [
    ("deepset/prompt-injections", "mixed", None),
    ("xTRam1/safe-guard-prompt-injection", "mixed", 600),
    ("jackhhao/jailbreak-classification", "mixed", 600),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", "mixed", 600),
    ("Lakera/gandalf_ignore_instructions", "attack_only", 400),
    ("hackaprompt/hackaprompt-dataset", "attack_only", 400),
    ("allenai/wildjailbreak", "contrast", 500),
]

MAXCHARS = 6000  # truncate pathological rows so a single prompt can't blow the ctx window


def balanced_sample(rows, cap, rng):
    if cap is None or len(rows) <= cap:
        return rows
    pos = [r for r in rows if r[1] == 1]
    neg = [r for r in rows if r[1] == 0]
    if not pos or not neg:  # single class -> plain sample
        rng.shuffle(rows)
        return rows[:cap]
    half = cap // 2
    rng.shuffle(pos)
    rng.shuffle(neg)
    take_pos = pos[: min(half, len(pos))]
    take_neg = neg[: min(cap - len(take_pos), len(neg))]
    # top up from the larger class if one side is short
    if len(take_pos) + len(take_neg) < cap:
        extra = pos[len(take_pos) :] + neg[len(take_neg) :]
        rng.shuffle(extra)
        take = take_pos + take_neg + extra[: cap - len(take_pos) - len(take_neg)]
    else:
        take = take_pos + take_neg
    rng.shuffle(take)
    return take


def main():
    rng = random.Random(SEED)
    out = []
    for name, kind, cap in SPEC:
        try:
            rows = load_binary(name)
        except Exception as e:
            print(f"[SKIP] {name}: {repr(e)[:160]}")
            continue
        rows = [(str(t)[:MAXCHARS], int(l)) for (t, l) in rows if t]
        rows = balanced_sample(rows, cap, rng)
        npos = sum(1 for _, l in rows if l == 1)
        print(f"[{name}] {len(rows)} rows | pos={npos} neg={len(rows) - npos} | kind={kind}")
        short = name.split("/")[-1]
        for i, (t, l) in enumerate(rows):
            out.append(
                {"id": f"{short}:{i}", "dataset": short, "text": t, "label": l, "kind": kind}
            )

    # NotInject (benign over-defense set)
    ds = load_dataset("leolee99/NotInject")
    rows = concatenate_datasets([ds[s] for s in ds.keys()])
    for i, r in enumerate(rows):
        out.append(
            {
                "id": f"NotInject:{i}",
                "dataset": "NotInject",
                "text": str(r["prompt"])[:MAXCHARS],
                "label": 0,
                "kind": "notinject",
            }
        )
    print(f"[NotInject] {len(rows)} benign rows")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")
    print(f"\nwrote {len(out)} rows -> {OUT}")


if __name__ == "__main__":
    main()
