"""Build a held-out DEV slice for EARLY-STOP / checkpoint selection, drawn from the eval
DATASETS but MECHANICALLY DISJOINT from the reported 4101-row eval_cache.jsonl test set.

Why: selecting checkpoints on the reported test cache = training on test = inflated leaderboard
numbers. build_cache.py capped most eval sources (safe-guard 600, jailbreak 600, SPML 600,
gandalf 400, hackaprompt 400) so the FULL datasets still hold rows that never entered the cache.
We take those leftover rows (+ darkknight benign, a source the eval cache never used, as a
trigger-bearing over-defense proxy) and hard-gate that NO dev row is identical (normalized-text /
sha1) to any test-cache row. Near-duplicate attack-family sharing is expected for a same-
distribution dev slice and is reported for transparency, not gated on -- what would corrupt the
metric is an IDENTICAL row leaking, which the gate forbids.

The dev metric (computed in train_lora's callback) is recall@1%FPR over this slice: benign pool =
dev label-0 (held-out in-dist benign + darkknight trigger-benign), positives = dev label-1. A
checkpoint that over-defends (flags the trigger-benign) raises the 1%-FPR threshold and loses
recall, so over-defense pressure is folded into the single maximized number.

Run on orchestrator (datasets cached):  HF_HUB_OFFLINE=1 python code/build_dev_slice.py
"""

import hashlib
import json
import os
import random
import re
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT.parents[1]
CACHE = REPO / "eval" / "results" / "qwen_scores" / "eval_cache.jsonl"
OUT = ROOT / "data" / "dev_slice.jsonl"
sys.path.insert(0, str(REPO / "eval"))
from run_injection_bench import load_binary
from datasets import load_dataset

SEED = 4242
MAXCHARS = 6000
NGRAM = 40

# (loader, kind, cap, take)  take = per-class cap for the dev slice
MIXED = [
    ("xTRam1/safe-guard-prompt-injection", 150),
    ("jackhhao/jailbreak-classification", 150),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", 150),
]
ATTACK = [
    ("Lakera/gandalf_ignore_instructions", 150),
    ("hackaprompt/hackaprompt-dataset", 150),
]


def norm(s):
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def sha(s):
    return hashlib.sha1(norm(s).encode()).hexdigest()


def char_ngrams(s, n=NGRAM):
    s = norm(s)
    return {s[i : i + n] for i in range(0, max(1, len(s) - n + 1))} if len(s) >= n else {s}


def main():
    rng = random.Random(SEED)
    cache = [json.loads(l) for l in CACHE.open()]
    cache_norm = {norm(c["text"]) for c in cache}
    cache_sha = {sha(c["text"]) for c in cache}

    out = []

    def keep(t):
        # gate against the SAME (6000-char truncated) form we store, matching build_cache
        t = (t or "")[:MAXCHARS]
        return t and norm(t) not in cache_norm and sha(t) not in cache_sha

    def add_rows(rows, kind, source, per_class):
        pos = [t[:MAXCHARS] for (t, l) in rows if l == 1 and keep(t)]
        neg = [t[:MAXCHARS] for (t, l) in rows if l == 0 and keep(t)]
        rng.shuffle(pos)
        rng.shuffle(neg)
        for t in pos[:per_class]:
            out.append({"text": t, "label": 1, "dataset": source, "kind": kind})
        for t in neg[:per_class]:
            out.append({"text": t, "label": 0, "dataset": source, "kind": kind})

    for name, take in MIXED:
        try:
            add_rows(load_binary(name), "mixed", name.split("/")[-1], take)
        except Exception as e:
            print(f"[skip] {name}: {repr(e)[:120]}")
    for name, take in ATTACK:
        try:
            add_rows(load_binary(name), "attack_only", name.split("/")[-1], take)
        except Exception as e:
            print(f"[skip] {name}: {repr(e)[:120]}")

    # darkknight benign = trigger-bearing benign, an over-defense proxy the eval cache never used
    try:
        ds = load_dataset("darkknight25/Prompt_Injection_Benign_Prompt_Dataset", split="train")
        ben = [str(r.get("prompt")) for r in ds if str(r.get("label", "")).lower() == "benign"]
        ben = [t[:MAXCHARS] for t in ben if keep(t)]
        rng.shuffle(ben)
        for t in ben[:250]:
            out.append(
                {"text": t, "label": 0, "dataset": "darkknight-benign", "kind": "overdefense_proxy"}
            )
    except Exception as e:
        print(f"[skip] darkknight benign: {repr(e)[:120]}")

    # ---- dedup within dev, assign ids ----
    seen, dev = set(), []
    for r in out:
        h = sha(r["text"])
        if h in seen:
            continue
        seen.add(h)
        r["id"] = f"dev:{len(dev)}"
        dev.append(r)
    rng.shuffle(dev)

    # ---- HARD GATE: zero identical rows vs the test cache ----
    leaks = [r for r in dev if norm(r["text"]) in cache_norm or sha(r["text"]) in cache_sha]
    assert not leaks, f"DEV/TEST LEAK: {len(leaks)} dev rows identical to eval_cache rows"

    # ---- informational near-duplicate report (NOT gated) ----
    cache_ng = set()
    for c in cache:
        cache_ng |= char_ngrams(c["text"])
    near = sum(1 for r in dev if char_ngrams(r["text"]) & cache_ng)

    npos = sum(1 for r in dev if r["label"] == 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        for r in dev:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"WROTE {len(dev)} dev rows -> {OUT}")
    print(f"  pos(attack)={npos} neg(benign)={len(dev) - npos}")
    print("  MECHANICAL DISJOINTNESS (identical-row) vs eval_cache: PASS (0 leaks)")
    print(
        f"  near-duplicate 40-char-span family overlap: {near}/{len(dev)} "
        f"(expected for same-distribution dev; NOT a leak)"
    )
    import collections

    print("  by source:", dict(collections.Counter(r["dataset"] for r in dev)))


if __name__ == "__main__":
    main()
