#!/usr/bin/env python3
"""Prove the few-shot exemplars have ZERO overlap with the 4101-row eval cache.

Checks, for every exemplar against every eval-cache row:
  1. exact normalized-text equality (whitespace/case-folded)  -> abort
  2. sha1 of normalized text collision                         -> abort
  3. long-substring containment either direction (>= NGRAM chars of one
     appearing inside the other, normalized)                   -> abort
  4. high token-Jaccard near-duplicate (>= JACC)               -> warn+abort

Exit 0 and print a proof line only if ALL exemplars are disjoint.
"""

import json
import re
import sys
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE.parent / "results" / "qwen_scores" / "eval_cache.jsonl"
BANK = HERE / "fewshot_bank.json"
NGRAM = 40  # chars: any 40-char normalized span shared -> treat as overlap
JACC = 0.6  # token-set Jaccard near-duplicate ceiling


def norm(s):
    return re.sub(r"\s+", " ", s.strip().lower())


def toks(s):
    return set(re.findall(r"\w+", s.lower()))


def char_ngrams(s, n=NGRAM):
    s = norm(s)
    return {s[i : i + n] for i in range(0, max(1, len(s) - n + 1))} if len(s) >= n else {s}


def main():
    cache = [json.loads(l) for l in CACHE.open()]
    bank = json.loads(BANK.read_text())["exemplars"]

    cache_norm = [norm(c["text"]) for c in cache]
    cache_hash = {hashlib.sha1(t.encode()).hexdigest() for t in cache_norm}
    cache_toks = [toks(c["text"]) for c in cache]

    fails = []
    for ei, ex in enumerate(bank):
        et = norm(ex["text"])
        eh = hashlib.sha1(et.encode()).hexdigest()
        etoks = toks(ex["text"])
        eng = char_ngrams(ex["text"])

        if eh in cache_hash:
            fails.append((ei, "EXACT-HASH-MATCH", ""))
            continue
        worst_j = 0.0
        worst_j_ex = ""
        ng_hit = None
        for ci, ct in enumerate(cache_norm):
            # substring containment (short exemplars: whole-text; long: ngram overlap)
            if et and (et in ct or ct in et):
                ng_hit = ("FULL-CONTAINMENT", cache[ci]["id"])
                break
            # shared long char-ngram
            if eng & char_ngrams(cache[ci]["text"]):
                ng_hit = ("NGRAM40-OVERLAP", cache[ci]["id"])
                break
            # jaccard
            u = etoks | cache_toks[ci]
            if u:
                j = len(etoks & cache_toks[ci]) / len(u)
                if j > worst_j:
                    worst_j, worst_j_ex = j, cache[ci]["id"]
        if ng_hit:
            fails.append((ei, ng_hit[0], ng_hit[1]))
        elif worst_j >= JACC:
            fails.append((ei, f"JACCARD={worst_j:.2f}", worst_j_ex))
        else:
            print(
                f"  exemplar[{ei}] '{ex['kind']}': OK  (max token-Jaccard vs any "
                f"eval row = {worst_j:.2f} @ {worst_j_ex})"
            )

    if fails:
        print("\nLEAKAGE DETECTED — aborting:")
        for ei, why, wid in fails:
            print(f"  exemplar[{ei}] '{bank[ei]['kind']}': {why} {wid}")
        sys.exit(1)
    print(
        f"\nPROOF: all {len(bank)} exemplars disjoint from all {len(cache)} eval-cache rows "
        f"(no exact/hash/40-char-substring/>= {JACC} Jaccard overlap). ZERO leakage."
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
