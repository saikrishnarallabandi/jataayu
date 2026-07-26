"""Rebuild the training set for the over-defense correction round:
  train_full (57.6k, ~28.8k attack / 28.8k benign)  +  NotInject-style hard-negs (label 0).

The hard-negs are UPWEIGHTED (oversampled) so the over-defense signal is strong, and the benign
side is deliberately dominated by them, while keeping ~50/50 LABEL balance. Result:
  attack = all original attacks
  benign = (hard-negs x oversample)  +  enough original benigns to match the attack count
So labels stay ~50/50 but the benign half is mostly hard-negs -- exactly the "stop over-flagging
trigger-dense benign" signal the frontier said we need.

Run:  python code/build_train_v2.py --hardneg-glob 'data/synth_vllm_shard*.jsonl' \
        --extra-hardneg 'data/synth_notinject_hardnegs.shard*.jsonl' --oversample 2 --out data/train_v2.jsonl
"""

import argparse
import glob
import json
import random
import re
from pathlib import Path

SCHEMA = ["id", "text", "label", "attack_type", "source", "split", "license"]


def norm(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def load_glob(pat):
    rows = []
    for p in sorted(glob.glob(pat)):
        for l in open(p):
            l = l.strip()
            if l:
                rows.append(json.loads(l))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-file", default="data/train_full.jsonl")
    ap.add_argument("--hardneg-glob", required=True)
    ap.add_argument(
        "--extra-hardneg", default=None, help="extra hard-neg glob (e.g. orchestrator shards)"
    )
    ap.add_argument("--oversample", type=int, default=2, help="hard-neg oversample factor")
    ap.add_argument("--out", default="data/train_v2.jsonl")
    ap.add_argument("--seed", type=int, default=20260716)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    base = [json.loads(l) for l in open(args.train_file) if l.strip()]
    base = [r for r in base if r.get("split") != "heldout"]
    attack = [r for r in base if int(r["label"]) == 1]
    obenign = [r for r in base if int(r["label"]) == 0]

    # hard-negs, deduped by normalized text (also against base benign to avoid trivial repeats)
    hn = load_glob(args.hardneg_glob)
    if args.extra_hardneg:
        hn += load_glob(args.extra_hardneg)
    seen = {norm(r["text"]) for r in base}
    uniq_hn, hn_seen = [], set()
    for r in hn:
        n = norm(r["text"])
        if n in seen or n in hn_seen or len(r["text"]) < 20:
            continue
        hn_seen.add(n)
        uniq_hn.append({k: r.get(k) for k in SCHEMA})
    rng.shuffle(uniq_hn)

    # oversample hard-negs, then fill the benign side to match the attack count (50/50 labels)
    hn_over = uniq_hn * args.oversample
    n_attack = len(attack)
    if len(hn_over) >= n_attack:
        benign_final = hn_over[:n_attack]
        n_orig_used = 0
    else:
        n_orig_used = n_attack - len(hn_over)
        rng.shuffle(obenign)
        benign_final = hn_over + obenign[:n_orig_used]

    final = attack + benign_final
    # re-id oversampled dups so ids stay unique
    out = []
    for i, r in enumerate(final):
        r = dict(r)
        r["id"] = (
            f"{r.get('id', 'row')}_{i}"
            if r.get("source") == "synth_notinject_hardneg"
            else r.get("id")
        )
        out.append({k: r.get(k) for k in SCHEMA})
    rng.shuffle(out)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    nb = sum(1 for r in out if int(r["label"]) == 0)
    print(f"WROTE {len(out)} -> {args.out}")
    print(f"  attack={len(attack)} benign={nb} ({100 * nb / len(out):.0f}% benign)")
    print(
        f"  unique hard-negs={len(uniq_hn)} x{args.oversample}={len(hn_over)} "
        f"(effective in benign side) + {n_orig_used} original benigns"
    )


if __name__ == "__main__":
    main()
