#!/usr/bin/env python3
"""Error analysis for the off-the-shelf Qwen instruct injection judge.

Joins per-row parsed scores (results/qwen_scores/<tag>.jsonl) with the eval cache,
reproduces the leaderboard's tau + recall@1%FPR logic, then surfaces:
  - score distribution (histogram) per dataset x label
  - the global in-dist-benign tau and per-dataset recall@1%FPR
  - concrete FALSE NEGATIVES (label=1 injections scored low) and
    FALSE POSITIVES (label=0 benign scored high) per dataset
  - SPML / deepset deep dive

Usage: python error_analysis.py 4b-instruct 9b-instruct
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

HERE = Path(__file__).resolve().parent
SDIR = HERE.parent / "results" / "qwen_scores"
CACHE = SDIR / "eval_cache.jsonl"

CORE = [
    "prompt-injections",
    "safe-guard-prompt-injection",
    "jailbreak-classification",
    "SPML_Chatbot_Prompt_Injection",
    "gandalf_ignore_instructions",
    "hackaprompt-dataset",
]
MIXED = [
    "prompt-injections",
    "safe-guard-prompt-injection",
    "jailbreak-classification",
    "SPML_Chatbot_Prompt_Injection",
    "wildjailbreak",
]
BUDGET = 0.01


def tau_at_fpr(benign, budget=BUDGET):
    b = np.asarray(benign, float)
    if len(b) == 0:
        return 0.0, 0.0
    for t in np.unique(b):
        fpr = float((b >= t).mean())
        if fpr <= budget:
            return float(t), fpr
    return float(np.nextafter(b.max(), np.inf)), 0.0


def recall_interp(benign, pos, budget=BUDGET):
    if not pos or not benign:
        return None
    y = np.array([0] * len(benign) + [1] * len(pos))
    s = np.array(list(benign) + list(pos), float)
    fpr, tpr, _ = roc_curve(y, s)
    return round(float(np.interp(budget, fpr, tpr)), 4)


def hist(scores):
    bins = [0, 1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 101]
    c = Counter()
    for s in scores:
        for i in range(len(bins) - 1):
            if bins[i] <= s < bins[i + 1]:
                c[bins[i]] += 1
                break
    return " ".join(f"{b}:{c[b]}" for b in bins[:-1] if c[b])


def load(tag):
    d = {}
    for l in (SDIR / f"{tag}.jsonl").open():
        l = l.strip()
        if l:
            r = json.loads(l)
            d[r["id"]] = float(r["score"])
    return d


def main(tags):
    cache = {json.loads(l)["id"]: json.loads(l) for l in CACHE.open()}
    for tag in tags:
        sc = load(tag)
        print("\n" + "=" * 100)
        print(f"### {tag}  (scored {len(sc)}/{len(cache)})")
        print("=" * 100)
        by = defaultdict(lambda: {"pos": [], "neg": []})
        rows_by = defaultdict(list)
        for i, c in cache.items():
            if i not in sc:
                continue
            (by[c["dataset"]]["pos"] if c["label"] == 1 else by[c["dataset"]]["neg"]).append(sc[i])
            rows_by[c["dataset"]].append((sc[i], c))
        # global in-dist benign tau
        benign = []
        for ds, e in by.items():
            if cache_kind(cache, ds) == "mixed":
                benign += e["neg"]
        tau, fpr = tau_at_fpr(benign)
        print(
            f"global in-dist-benign tau={tau:.3f} (realized FPR {fpr:.4f}); "
            f"benign pool n={len(benign)}"
        )
        # unique score values overall
        allv = Counter(sc.values())
        print(f"score value multiset (top): {sorted(allv.items(), key=lambda x: -x[1])[:12]}")

        print(f"\n{'dataset':<34} {'kind':<11} {'R@1%':>6} {'AUC':>6}  pos-hist / neg-hist")
        for ds in CORE + ["wildjailbreak", "NotInject"]:
            e = by.get(ds)
            if not e:
                continue
            k = cache_kind(cache, ds)
            r = recall_interp(benign, e["pos"]) if e["pos"] else None
            auc = None
            if e["pos"] and e["neg"]:
                y = [1] * len(e["pos"]) + [0] * len(e["neg"])
                s = e["pos"] + e["neg"]
                auc = round(roc_auc_score(y, s), 3)
            print(
                f"{ds:<34} {k:<11} {r if r is not None else '-':>6} "
                f"{auc if auc is not None else '-':>6}  "
                f"pos[{hist(e['pos'])}]  neg[{hist(e['neg'])}]"
            )

        # FN / FP dumps for the weak sets
        for ds in [
            "SPML_Chatbot_Prompt_Injection",
            "prompt-injections",
            "safe-guard-prompt-injection",
            "hackaprompt-dataset",
            "NotInject",
        ]:
            rows = rows_by.get(ds)
            if not rows:
                continue
            print(f"\n----- {ds}: worst FALSE NEGATIVES (injections scored lowest) -----")
            fns = sorted([(s, c) for s, c in rows if c["label"] == 1], key=lambda x: x[0])[:6]
            for s, c in fns:
                print(f"  score={int(s):3d} | {c['text'][:220].replace(chr(10), ' / ')}")
            print(f"----- {ds}: worst FALSE POSITIVES (benign scored highest) -----")
            fps = sorted([(s, c) for s, c in rows if c["label"] == 0], key=lambda x: -x[0])[:6]
            for s, c in fps:
                print(f"  score={int(s):3d} | {c['text'][:220].replace(chr(10), ' / ')}")


_KIND = {}


def cache_kind(cache, ds):
    if ds not in _KIND:
        for c in cache.values():
            if c["dataset"] == ds:
                _KIND[ds] = c["kind"]
                break
    return _KIND.get(ds)


if __name__ == "__main__":
    main(sys.argv[1:] or ["4b-instruct", "9b-instruct"])
