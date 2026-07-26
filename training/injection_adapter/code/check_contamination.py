"""Independent contamination + license audit for a finished training file.

Deliberately shares NO code with assemble.py's gate: it re-derives the exclusion set from the
eval cache and re-reads the finished file from disk. "The gate reported success" and "the file
on disk is clean" are two different claims, and only the second one matters.

Reports both directions of the overlap, because they differ and the published 41.8% figure was
the eval-side one:
  train-side = training rows whose text is in the eval cache
  eval-side  = eval rows whose text is in the training file  (the contamination headline)

Exit 1 if any overlap or any disqualified source survives, so this can gate a training run.

Run:  eval/.venv-hf/bin/python code/check_contamination.py data/train_v2_clean.jsonl
      ... --baseline data/train_v2.jsonl      # adds a before/after table
"""

import argparse
import collections
import json
import re
import sys
import unicodedata

DISQUALIFIED = (
    "xTRam1/safe-guard-prompt-injection",
    "deepset/prompt-injections",
    "darkknight25/Prompt_Injection_Benign_Prompt_Dataset",
)


def norm(s):
    s = unicodedata.normalize("NFKC", str(s or "")).lower().strip()
    return re.sub(r"\s+", " ", s)


def load(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def summarize(rows):
    lab = collections.Counter(int(r["label"]) for r in rows)
    return len(rows), lab[0], lab[1], collections.Counter(r.get("source") for r in rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("train_file")
    ap.add_argument("--eval-cache", default="../../eval/results/qwen_scores/eval_cache.jsonl")
    ap.add_argument("--baseline", default=None, help="prior train file for a before/after table")
    args = ap.parse_args()

    ev = load(args.eval_cache)
    tr = load(args.train_file)
    ev_texts = {norm(r["text"]) for r in ev}
    tr_texts = {norm(r["text"]) for r in tr}

    n, n0, n1, by_src = summarize(tr)
    print(f"FILE: {args.train_file}")
    print(f"  rows={n}  label0(benign)={n0}  label1(attack)={n1}  benign_frac={n0 / max(1, n):.3f}")

    print("\nPER-SOURCE:")
    for s, c in by_src.most_common():
        print(f"  {s:56s} {c:6d}")

    print("\nDISQUALIFIED-SOURCE CHECK (must all be 0):")
    lic_fail = 0
    for s in DISQUALIFIED:
        c = by_src.get(s, 0)
        lic_fail += c
        print(f"  {s:56s} {c:6d}  {'OK' if c == 0 else 'FAIL'}")

    train_side = [r for r in tr if norm(r["text"]) in ev_texts]
    eval_side = [r for r in ev if norm(r["text"]) in tr_texts]
    print("\nVERBATIM OVERLAP WITH EVAL CACHE (must be 0):")
    print(f"  eval cache rows            : {len(ev)}  ({len(ev_texts)} unique normalized)")
    print(f"  train-side (train rows hit): {len(train_side)}")
    print(
        f"  eval-side  (eval rows hit) : {len(eval_side)}  "
        f"= {100 * len(eval_side) / max(1, len(ev)):.1f}% of the eval suite"
    )

    # Raw, unnormalized. Mathematically this can only be a subset of the normalized overlap
    # (equal raw strings normalize equal), so it is a self-check on the normalizer, not a second
    # gate: raw > normalized would mean norm() is dropping a collision it should have caught.
    ev_raw = {str(r["text"]) for r in ev}
    tr_raw = {str(r["text"]) for r in tr}
    raw_train_side = sum(1 for r in tr if str(r["text"]) in ev_raw)
    raw_eval_side = sum(1 for r in ev if str(r["text"]) in tr_raw)
    print(f"  RAW train-side (unnormalized): {raw_train_side}")
    print(f"  RAW eval-side  (unnormalized): {raw_eval_side}")
    if raw_train_side > len(train_side) or raw_eval_side > len(eval_side):
        print("  ERROR: raw overlap exceeds normalized overlap; norm() is unsound.")
    if train_side:
        print(
            "  offending sources:", dict(collections.Counter(r.get("source") for r in train_side))
        )
        for r in train_side[:5]:
            print(f"    - {r.get('id')} ({r.get('source')}): {r['text'][:90]!r}")

    if args.baseline:
        b = load(args.baseline)
        bn, bn0, bn1, b_by = summarize(b)
        b_texts = {norm(r["text"]) for r in b}
        b_eval_side = sum(1 for r in ev if norm(r["text"]) in b_texts)
        print(f"\nBEFORE/AFTER  ({args.baseline} -> {args.train_file})")
        print(f"  {'metric':<56s} {'before':>8s} {'after':>8s} {'delta':>8s}")
        print(f"  {'total rows':<56s} {bn:>8d} {n:>8d} {n - bn:>+8d}")
        print(f"  {'label 0 (benign)':<56s} {bn0:>8d} {n0:>8d} {n0 - bn0:>+8d}")
        print(f"  {'label 1 (attack)':<56s} {bn1:>8d} {n1:>8d} {n1 - bn1:>+8d}")
        print(
            f"  {'eval rows contaminating train':<56s} "
            f"{b_eval_side:>8d} {len(eval_side):>8d} {len(eval_side) - b_eval_side:>+8d}"
        )
        print("  --- rows per source ---")
        for s in sorted(set(b_by) | set(by_src)):
            print(
                f"  {s:<56s} {b_by.get(s, 0):>8d} {by_src.get(s, 0):>8d} "
                f"{by_src.get(s, 0) - b_by.get(s, 0):>+8d}"
            )

    ok = not train_side and not eval_side and not lic_fail
    print(f"\nVERDICT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
