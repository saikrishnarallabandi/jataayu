"""Build a balanced, source-diverse dataset from the Layer-1 pool + synthesized negatives,
then validate it. Used for BOTH the small sample and the full train build.

Auto-balances to ~50/50 label and ~60/40 indirect/direct AMONG POSITIVES, capped by real
availability. HELDOUT rows are excluded and a hard assertion guarantees zero heldout leakage.

Small sample (approved):
  build_sample.py --pool data/layer1_pool.jsonl \
     --tool-returns "data/synth_tool_returns.jsonl" --hard-negs "data/synth_hard_negatives.jsonl" \
     --out data/sample_v0.jsonl --n-direct-pos 110 --n-indirect-pos 165 \
     --n-layer1-benign 115 --n-tool-returns 110 --n-hard-negs 50 --no-auto-balance

Full build:
  build_sample.py --pool data/layer1_pool_full.jsonl \
     --tool-returns "data/synth_tool_returns_full*.jsonl" \
     --hard-negs "data/synth_hard_negatives_full*.jsonl" \
     --out data/train_full.jsonl --auto-balance
"""

import argparse
import collections
import glob
import json
import random

SCHEMA = ["id", "text", "label", "attack_type", "source", "split", "license"]
HELDOUT_SOURCES = {
    "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1",  # Nemotron-IPI
    # NotInject / AgentDojo / InjecAgent live in eval/ and are never loaded into the pool,
    # but we still hard-guard against any source tagged heldout leaking into the train set.
}
TRIGGERS = [
    "ignore all previous",
    "ignore previous",
    "ignore my previous",
    "disregard previous",
    "system:",
    "system prompt",
    "you are now",
    "new instructions",
    "reveal your",
    "dan",
    "forget your",
    "override",
]


def load_glob(pattern):
    rows = []
    if not pattern:
        return rows
    for path in sorted(glob.glob(pattern)):
        for line in open(path):
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def dedup_by_id(rows):
    seen, out = set(), []
    for r in rows:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        out.append(r)
    return out


def round_robin(by_src, k, rng):
    for v in by_src.values():
        rng.shuffle(v)
    srcs = [s for s in by_src if by_src[s]]
    out, i = [], 0
    while len(out) < k and any(by_src[s] for s in srcs):
        s = srcs[i % len(srcs)]
        if by_src[s]:
            out.append(by_src[s].pop())
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="data/layer1_pool.jsonl")
    ap.add_argument("--tool-returns", default="data/synth_tool_returns.jsonl")
    ap.add_argument("--hard-negs", default="data/synth_hard_negatives.jsonl")
    ap.add_argument("--out", default="data/sample_v0.jsonl")
    ap.add_argument("--seed", type=int, default=20260715)
    ap.add_argument("--n-indirect-pos", type=int, default=165)
    ap.add_argument("--n-direct-pos", type=int, default=110)
    ap.add_argument("--n-layer1-benign", type=int, default=115)
    ap.add_argument("--n-tool-returns", type=int, default=110)
    ap.add_argument("--n-hard-negs", type=int, default=50)
    ap.add_argument(
        "--auto-balance",
        action="store_true",
        help="ignore explicit n-* and auto-size to max balanced set (50/50, pos 60/40)",
    )
    ap.add_argument("--no-auto-balance", dest="auto_balance", action="store_false")
    ap.add_argument("--indirect-frac", type=float, default=0.60)
    ap.add_argument(
        "--hardneg-frac",
        type=float,
        default=0.12,
        help="hard-negs as fraction of negatives (auto-balance)",
    )
    ap.add_argument(
        "--toolret-frac",
        type=float,
        default=0.58,
        help="tool-returns as fraction of negatives (auto-balance)",
    )
    args = ap.parse_args()
    rng = random.Random(args.seed)

    pool_all = load_glob(args.pool)
    pool = [r for r in pool_all if r.get("split") == "train"]
    heldout = [r for r in pool_all if r.get("split") == "heldout"]
    tr = dedup_by_id(load_glob(args.tool_returns))
    hn = dedup_by_id(load_glob(args.hard_negs))

    indirect_pos = [r for r in pool if r["label"] == 1 and r["attack_type"] == "indirect"]
    direct_pos = [r for r in pool if r["label"] == 1 and r["attack_type"] == "direct"]
    layer1_benign = [r for r in pool if r["label"] == 0]
    rng.shuffle(indirect_pos)
    rng.shuffle(direct_pos)
    rng.shuffle(layer1_benign)
    rng.shuffle(tr)
    rng.shuffle(hn)

    if args.auto_balance:
        # positives: hold indirect_frac; bind on whichever positive class is scarce
        f = args.indirect_frac
        di = len(direct_pos)
        ii = len(indirect_pos)
        # try direct as (1-f) share: total_pos = direct/(1-f); need indirect >= total_pos*f
        pos_direct = min(di, int(ii * (1 - f) / f))
        pos_indirect = min(ii, int(round(pos_direct * f / (1 - f))))
        total_pos = pos_indirect + pos_direct
        # negatives = total_pos, composed with fracs but capped by availability
        want_hn = min(len(hn), int(total_pos * args.hardneg_frac))
        want_tr = min(len(tr), int(total_pos * args.toolret_frac))
        want_l1 = total_pos - want_hn - want_tr
        if want_l1 > len(layer1_benign):
            # top up shortfall from remaining tool-returns
            short = want_l1 - len(layer1_benign)
            want_l1 = len(layer1_benign)
            want_tr = min(len(tr), want_tr + short)
        # final top-up if still short of total_pos
        neg_have = want_hn + want_tr + want_l1
        if neg_have < total_pos:
            extra = min(len(tr) - want_tr, total_pos - neg_have)
            want_tr += extra
        n_ind, n_dir, n_l1, n_tr, n_hn = pos_indirect, pos_direct, want_l1, want_tr, want_hn
    else:
        n_ind, n_dir = args.n_indirect_pos, args.n_direct_pos
        n_l1, n_tr, n_hn = args.n_layer1_benign, args.n_tool_returns, args.n_hard_negs

    sel = []
    sel += indirect_pos[:n_ind]
    by_src = collections.defaultdict(list)
    for r in direct_pos:
        by_src[r["source"]].append(r)
    sel += round_robin(by_src, n_dir, rng)
    # layer1 benign spread across sources too
    by_src_b = collections.defaultdict(list)
    for r in layer1_benign:
        by_src_b[r["source"]].append(r)
    sel += round_robin(by_src_b, n_l1, rng)
    sel += tr[:n_tr]
    sel += hn[:n_hn]

    final = dedup_by_id(sel)
    # ---- HARD heldout-leakage guard ----
    leaked = [r for r in final if r.get("split") == "heldout" or r["source"] in HELDOUT_SOURCES]
    assert not leaked, f"HELDOUT LEAK: {len(leaked)} heldout rows in train set!"
    final = [{k: r.get(k) for k in SCHEMA} for r in final]
    rng.shuffle(final)

    with open(args.out, "w") as f:
        for r in final:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # ---- validation ----
    tot = len(final)
    lab = collections.Counter(r["label"] for r in final)
    pos = [r for r in final if r["label"] == 1]
    pat = collections.Counter(r["attack_type"] for r in pos)
    print(f"WROTE {tot} rows -> {args.out}\n")
    print(
        f"pool train-eligible={len(pool)} heldout={len(heldout)} | "
        f"synth tool-returns avail={len(tr)} hard-negs avail={len(hn)}"
    )
    print(f"schema ok: {all(all(k in r for k in SCHEMA) for r in final)}")
    print(f"label balance: benign(0)={lab[0]} attack(1)={lab[1]}  benign_frac={lab[0] / tot:.3f}")
    print(
        f"positives: {len(pos)} | indirect={pat['indirect']} direct={pat['direct']} "
        f"indirect_frac(among-pos)={pat['indirect'] / max(1, len(pos)):.3f}"
    )

    # by-CHANNEL across ALL rows: benign tool-returns occupy the indirect channel
    def channel(r):
        if r["attack_type"] == "indirect" or r["source"] == "synth_tool_returns":
            return "indirect"
        return "direct"

    ch = collections.Counter(channel(r) for r in final)
    print(
        f"by-channel (all rows): indirect={ch['indirect']} direct={ch['direct']} "
        f"indirect_frac={ch['indirect'] / tot:.3f}"
    )
    print(f"HELDOUT LEAKAGE: {len(leaked)}  (must be 0)")
    print("\nby source x label:")
    sl = collections.Counter((r["source"], r["label"]) for r in final)
    for (s, l), c in sorted(sl.items()):
        print(f"  {s:52s} label={l}  n={c}")
    hns = [r for r in final if r["source"] == "synth_hard_negatives"]
    with_trig = sum(1 for r in hns if any(t in r["text"].lower() for t in TRIGGERS))
    print(
        f"\nhard-negatives: {len(hns)} | contain trigger: {with_trig} | "
        f"all label 0: {all(r['label'] == 0 for r in hns)}"
    )
    trs = [r for r in final if r["source"] == "synth_tool_returns"]
    leak = [
        r
        for r in trs
        if "ignore previous" in r["text"].lower() or "ignore all previous" in r["text"].lower()
    ]
    print(
        f"tool-returns: {len(trs)} | all label 0: {all(r['label'] == 0 for r in trs)} | "
        f"injection-leak: {len(leak)}"
    )


if __name__ == "__main__":
    main()
