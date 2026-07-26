"""Drop training rows that are near-duplicates of the frozen eval suite.

Verbatim exclusion (assemble.py's gate) is not enough: these corpora are templated, so an eval
row and a training row can differ by one substituted noun and still be the same item. Similarity
is token-5-gram Jaccard over the SAME normalization the 41.8% contamination was measured with.

THRESHOLD IS 0.90 AND ONLY 0.90. The 0.70-0.90 band is reported but deliberately NOT filtered:
in templated corpora that band IS the legitimate attack distribution the model has to learn, and
cutting it deletes the task rather than the leak.

PAIR ATOMICITY OUTRANKS THE FILTER. Counterfactual-pair arms are the whole reason the v3 recipe
exists -- a marker is label-neutral only because both arms carry it. Dropping one arm and keeping
its twin re-creates the authority-framing skew this build exists to remove, so it is worse than
keeping a near-duplicate. When any arm is filtered, the WHOLE pair goes. Train rows have pair_id
stripped by build_train_v3, so membership is recovered from the pair shards by arm id.

Run:  eval/.venv-hf/bin/python code/filter_near_dupes.py \
        data/train_v3_clean.prefilter.jsonl data/train_v3_clean.jsonl \
        --cfp-glob 'data/synth_cfp_haiku.shard*.jsonl'
      ... --verify-only          # recompute the bands on a finished file, write nothing
"""

import argparse
import collections
import glob
import json
import re
import sys
import unicodedata
from pathlib import Path

DEFAULT_EVAL_CACHE = "../../eval/results/qwen_scores/eval_cache.jsonl"
N = 5


def norm(s):
    s = unicodedata.normalize("NFKC", str(s or "")).lower().strip()
    return re.sub(r"\s+", " ", s)


def grams(text):
    """Token 5-grams. Documents shorter than N have no 5-gram, so they would compare as
    similarity 0 against everything -- including a verbatim copy of themselves. They fall back to
    the whole token tuple, which keeps short eval rows (many are one short sentence) inside the
    filter instead of silently exempt from it."""
    toks = norm(text).split()
    if not toks:
        return frozenset()
    if len(toks) < N:
        return frozenset({tuple(toks)})
    return frozenset(tuple(toks[i : i + N]) for i in range(len(toks) - N + 1))


def load(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


class EvalIndex:
    """Inverted 5-gram index over the eval suite, with the exact size bound for a Jaccard floor.

    For gram sets a,b with |a|<=|b|, J(a,b) >= t implies |a|/|b| >= t. Eval docs outside that size
    window cannot reach the floor, so skipping them is exact, not an approximation -- it never
    hides a hit at or above `floor`."""

    def __init__(self, rows, floor):
        self.floor = floor
        self.sets = [grams(r["text"]) for r in rows]
        self.sizes = [len(g) for g in self.sets]
        self.post = collections.defaultdict(list)
        for i, g in enumerate(self.sets):
            for gr in g:
                self.post[gr].append(i)

    def max_sim(self, text):
        a = grams(text)
        na = len(a)
        if not na:
            return 0.0
        lo, hi = na * self.floor, na / self.floor
        shared = collections.Counter()
        for gr in a:
            for i in self.post.get(gr, ()):
                if lo <= self.sizes[i] <= hi:
                    shared[i] += 1
        best = 0.0
        for i, s in shared.items():
            j = s / (na + self.sizes[i] - s)
            if j > best:
                best = j
        return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("in_file")
    ap.add_argument("out_file", nargs="?")
    ap.add_argument("--eval-cache", default=DEFAULT_EVAL_CACHE)
    ap.add_argument("--threshold", type=float, default=0.90)
    ap.add_argument("--band-low", type=float, default=0.70)
    ap.add_argument(
        "--cfp-glob",
        default=None,
        help="pair shards; required whenever the file contains pair arms",
    )
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()
    if not args.verify_only and not args.out_file:
        raise SystemExit("FATAL: out_file is required unless --verify-only")
    if args.band_low > args.threshold:
        raise SystemExit("FATAL: --band-low must be <= --threshold")

    ev = load(args.eval_cache)
    tr = load(args.in_file)
    ev_norm = {norm(r["text"]) for r in ev}
    idx = EvalIndex(ev, args.band_low)
    print(f"eval cache: {len(ev)} rows ({len(ev_norm)} unique normalized) from {args.eval_cache}")
    print(f"input     : {len(tr)} rows from {args.in_file}")

    sims = [idx.max_sim(r["text"]) for r in tr]
    # An exact normalized match must drop even if its gram set is empty (a whitespace-only row
    # scores 0.0 against everything), so the verbatim rule is enforced alongside the similarity one.
    flagged = {
        i for i, s in enumerate(sims) if s >= args.threshold or norm(tr[i]["text"]) in ev_norm
    }

    # ---- pair atomicity: a flagged arm condemns its whole pair ----
    arm_pair, pair_arms = {}, collections.defaultdict(set)
    if args.cfp_glob:
        for p in sorted(glob.glob(args.cfp_glob)):
            for line in open(p):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if r.get("pair_id") and r.get("id"):
                    arm_pair[r["id"]] = r["pair_id"]
                    pair_arms[r["pair_id"]].add(r["id"])
    by_id = collections.defaultdict(list)
    for i, r in enumerate(tr):
        by_id[r.get("id")].append(i)

    pair_sources = {r.get("source") for r in tr if r.get("id") in arm_pair}
    if not args.cfp_glob:
        orphan_risk = [r for r in tr if r.get("source") == "synth_counterfactual_pairs"]
        if orphan_risk:
            raise SystemExit(
                f"FATAL: {len(orphan_risk)} counterfactual-pair rows in {args.in_file} but no "
                "--cfp-glob given; the filter could drop one arm and orphan its twin."
            )

    condemned_pairs = {arm_pair[tr[i]["id"]] for i in flagged if tr[i].get("id") in arm_pair}
    twins = set()
    for pid in condemned_pairs:
        for aid in pair_arms[pid]:
            for i in by_id.get(aid, ()):
                if i not in flagged:
                    twins.add(i)
    drop = flagged | twins

    kept = [r for i, r in enumerate(tr) if i not in drop]
    # A pair arm surviving without its twin is the one outcome that must never ship.
    surv = collections.Counter(arm_pair[r["id"]] for r in kept if r.get("id") in arm_pair)
    broken = [pid for pid, c in surv.items() if c != len(pair_arms[pid])]
    if broken:
        raise SystemExit(f"FATAL: {len(broken)} pair(s) left orphaned arms, e.g. {broken[:5]}")

    band = [i for i, s in enumerate(sims) if args.band_low <= s < args.threshold and i not in drop]
    print(f"\nNEAR-DUP FILTER  (token-{N}-gram Jaccard vs eval cache, threshold {args.threshold})")
    print(f"  flagged >= {args.threshold:.2f} (incl. verbatim) : {len(flagged)}")
    print(
        f"  pairs condemned                    : {len(condemned_pairs)}"
        f"  (+{len(twins)} twin arm(s) dropped for atomicity)"
    )
    print(f"  total dropped                      : {len(drop)}")
    print(f"  kept                               : {len(kept)}")
    print(
        f"  residual in [{args.band_low:.2f}, {args.threshold:.2f}) band (NOT filtered): {len(band)}"
    )
    if pair_sources:
        print(
            f"  pair arms tracked                  : {sum(1 for r in tr if r.get('id') in arm_pair)}"
            f" rows, sources={sorted(pair_sources)}"
        )

    if drop:
        print("\n  dropped by source:")
        for s, c in collections.Counter(tr[i].get("source") for i in sorted(drop)).most_common():
            print(f"    {s:56s} {c:6d}")
        print(
            "  dropped by label:",
            dict(collections.Counter(int(tr[i]["label"]) for i in sorted(drop))),
        )
        print("  examples:")
        for i in sorted(drop)[:5]:
            print(
                f"    - sim={sims[i]:.3f} {tr[i].get('id')} ({tr[i].get('source')}): "
                f"{tr[i]['text'][:80]!r}"
            )
    if band:
        print("\n  residual band by source (kept, by design):")
        for s, c in collections.Counter(tr[i].get("source") for i in band).most_common(10):
            print(f"    {s:56s} {c:6d}")

    if args.verify_only:
        ok = not drop
        print(
            f"\nVERIFY-ONLY: {'PASS' if ok else 'FAIL'} "
            f"({len(drop)} row(s) at or above {args.threshold})"
        )
        return 0 if ok else 1

    Path(args.out_file).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out_file, "w") as f:
        for r in kept:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    lab = collections.Counter(int(r["label"]) for r in kept)
    print(f"\nWROTE {len(kept)} rows -> {args.out_file}")
    print(
        f"  label0(benign)={lab[0]} label1(attack)={lab[1]} "
        f"benign_frac={lab[0] / max(1, len(kept)):.3f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
