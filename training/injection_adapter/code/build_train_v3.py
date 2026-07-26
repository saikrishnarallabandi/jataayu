"""Rebuild the training set for the authority-blindspot correction round (v3):
  train_full  +  counterfactual PAIRS (--cfp-glob)  +  NotInject-style hard-negs (label 0).

v0.1 learned "SYSTEM: => benign" because v2's benign side was ~100% trigger-dense hard-negs at
oversample=2, with no trigger-dense POSITIVES to balance them (see
docs/finding-finetuning-induces-authority-blindspot.md). v3 changes three things:

  1. Counterfactual pairs are folded in ATOMICALLY and routed by their OWN label -- each pair_id's
     attack arm goes to the attack side and its benign twin to the benign side, so a surface marker
     carried by both arms is label-neutral by construction.
  2. --oversample defaults to 1 (was 2). The 2x upweight is what doubled the benign SYSTEM: rows.
  3. --balance-markers CAPS the benign side per marker (see below).

WHY (3) IS NEEDED ON TOP OF (1) AND (2). Pairs alone do not fix the skew, they only dilute it: 5,000
pairs moved `SYSTEM:` from 112:1 to 6.14:1 benign, because ~2,000 UNPAIRED trigger-dense benigns
(the REQUIRED_TRIGGERS generators) still sit on the benign side with no positive twin. Diluting is
asymptotic -- ~8,000 further system_colon pairs would buy only 1.2:1 -- so the invariant is enforced
directly instead: for each marker, benign rows <= attack rows * --marker-tolerance. The pair benign
twins already do the anti-over-defense job the unpaired hard-negs were added for, and they do it
correctly (each is anchored to an attack sharing its marker), which makes the unpaired ones both
redundant and actively harmful. Dropping them is a real over-defense RISK; it is left MEASURABLE
(paired accuracy + NotInject OD-acc at train time) and is deliberately NOT compensated for here.

PAIR ATOMICITY IS THE HARD INVARIANT, and it outranks the ratio. A pair is included whole or
excluded whole -- in train, in dev, or dropped. No dedup / truncation / class-balancing / shuffle /
MARKER-BALANCING step may separate arms: one arm alone re-creates the very skew this build removes,
so it is worse than not adding the pair at all. Pair arms are never candidates for downsampling;
they are balance-neutral anyway (a pair adds one row to each side). Pairs are NOT hard-negs and
never enter the hard-neg pool.

Run:  python code/build_train_v3.py --hardneg-glob 'data/synth_vllm_shard*.jsonl' \
        --extra-hardneg 'data/synth_notinject_hardnegs.shard*.jsonl' \
        --cfp-glob 'data/synth_cfp_haiku.shard*.jsonl' \
        --out data/train_v3.jsonl --cfp-dev-out data/cfp_dev.jsonl

Audit any built file with:  python code/marker_audit.py data/train_v3.jsonl
"""

import argparse
import glob
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from synth_counterfactual_pairs import AUTH_MARKERS  # noqa: E402

SCHEMA = ["id", "text", "label", "attack_type", "source", "split", "license"]
DEV_SCHEMA = SCHEMA + ["pair_id", "class"]  # the checkpoint-selection metric needs both

# The markers to balance are DERIVED from the pair generator's own AUTH_MARKERS list, not copied:
# a hardcoded copy silently goes stale the moment a marker is added there, and a marker the pairs
# cover but the balancer does not is exactly how the skew survives unnoticed.
#
# Only the whitespace/format variants are ours. They matter OUTSIDE the pair data (the generator's
# gate requires its literal verbatim, so within the pairs strict == loose on all 10,000 rows): it is
# the hard-neg pool, synth_tool_returns and the public corpora that emit `"role":"system"` unspaced
# or `## Instruction`. Every pattern is asserted below to match its own literal, so a variant that
# drifts away from the marker it claims to widen fails the build instead of silently counting zero.
MARKER_VARIANTS = {
    "json_block": r'"role"\s*:\s*"system"',
    "instruction_hdr": r"#{2,6}\s*instruction",
    "im_start": r"<\|im_start\|>\s*system",
    "admin_tag": r"\[\s*admin\s*\]",
    "sec_team": r"note from the (?:security|infosec) team\s*:",
}


def _marker_patterns():
    names = {name for name, _lit, _desc in AUTH_MARKERS}
    unknown = set(MARKER_VARIANTS) - names
    if unknown:
        raise SystemExit(
            f"FATAL: MARKER_VARIANTS names {sorted(unknown)}, which are not markers in "
            "synth_counterfactual_pairs.AUTH_MARKERS -- the variant list has drifted."
        )
    pats = {}
    for name, lit, _desc in AUTH_MARKERS:
        # re.I and NO re.M / no '^' anchor, deliberately: a mid-sentence "... the SYSTEM: block ..."
        # carries the marker just as a line-initial one does, and line-anchoring it has twice now
        # undercounted the benign side and hidden the skew this build exists to remove.
        c = re.compile(MARKER_VARIANTS.get(name, re.escape(lit)), re.I)
        if not c.search(lit):
            raise SystemExit(
                f"FATAL: pattern for marker {name!r} does not match its own literal "
                f"{lit!r}; it would count nothing."
            )
        pats[name] = c
    return pats


MARKERS = _marker_patterns()


def markers_in(text):
    return [n for n, c in MARKERS.items() if c.search(text or "")]


def norm(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def load_glob(pat, tolerate_partial=False):
    """Read jsonl shards. A synth batch may still be appending, so the final line of a shard can be
    a truncated record; skip it rather than crash. Any OTHER malformed line is a real corruption."""
    rows, skipped = [], 0
    for p in sorted(glob.glob(pat)):
        lines = open(p).read().splitlines()
        for i, l in enumerate(lines):
            l = l.strip()
            if not l:
                continue
            try:
                rows.append(json.loads(l))
            except json.JSONDecodeError:
                is_last = i == len(lines) - 1
                if tolerate_partial and is_last:
                    skipped += 1
                    continue
                raise SystemExit(
                    f"FATAL: malformed json at {p}:{i + 1} (not a trailing partial write)"
                )
    return rows, skipped


def load_pairs(pat):
    """Group cfp rows by pair_id. Returns (pairs, stats). A pair is USABLE only if it has >=2 arms
    and carries both an attack (label=1) and a benign (label=0) arm -- a half-written pair on disk
    would otherwise contribute a lone arm, which is the exact failure this builder exists to avoid.
    3+ arms are tolerated (an exfil third arm exists elsewhere in this work)."""
    rows, partial = load_glob(pat, tolerate_partial=True)
    by_id = defaultdict(list)
    no_pair_id = 0
    for r in rows:
        pid = r.get("pair_id")
        if not pid:
            no_pair_id += 1
            continue
        by_id[pid].append(r)

    usable, dropped_incomplete = {}, []
    for pid, arms in by_id.items():
        labels = {int(a["label"]) for a in arms}
        if len(arms) < 2 or 1 not in labels or 0 not in labels:
            dropped_incomplete.append(pid)
            continue
        usable[pid] = arms
    stats = dict(
        rows=len(rows),
        partial_lines=partial,
        no_pair_id=no_pair_id,
        seen_pairs=len(by_id),
        usable=len(usable),
        dropped_incomplete=len(dropped_incomplete),
    )
    return usable, stats


def fill_benign_balanced(hn_over, obenign, cfp_benign, attack_rows, room, tolerance, rng):
    """Admit unpaired benign rows in the SAME order the unbalanced build uses -- hard-negs first,
    originals to top up -- but never let a marker's benign count pass attack_count * tolerance.

    The cap covers the ORIGINAL benigns too, not just the hard-neg pool. train_full ships 3,000
    `synth_hard_negatives` rows of its own (the same REQUIRED_TRIGGERS generator) as ordinary label-0
    rows, so a top-up that ignored markers would re-import through the back door exactly the skew the
    hard-neg cap just removed.

    Pair arms (cfp_benign) are counted AGAINST the budget but are never candidates for dropping:
    atomicity outranks the ratio. They cannot overrun it anyway -- a pair contributes one row to each
    side, so protected[m] <= attack_count[m] <= budget[m] for tolerance >= 1.

    Returns (benign_final, n_hn_used, n_orig_used, report).
    """
    attack_cnt, protected_cnt = Counter(), Counter()
    for r in attack_rows:
        for m in markers_in(r["text"]):
            attack_cnt[m] += 1
    for r in cfp_benign:
        for m in markers_in(r["text"]):
            protected_cnt[m] += 1
    budget = {m: int(attack_cnt[m] * tolerance) for m in MARKERS}
    used = Counter(protected_cnt)

    rng.shuffle(obenign)  # same rng draw the unbalanced path makes, in the same place
    admitted, capped, n_hn = [], Counter(), 0
    for i, r in enumerate(hn_over + obenign):
        if len(admitted) >= room:
            break
        ms = markers_in(r["text"])
        blocking = [m for m in ms if used[m] >= budget[m]]
        if blocking:
            for m in blocking:
                capped[m] += 1
            continue
        for m in ms:
            used[m] += 1
        admitted.append(r)
        if i < len(hn_over):
            n_hn += 1

    def ratio(m):
        # 0 benign rows is 0 skew, even against 0 attacks: the marker is absent or fully capped, and
        # either way it cannot teach "benign". Only benigns with NO attack to balance them are inf.
        if not used[m]:
            return 0.0
        return used[m] / attack_cnt[m] if attack_cnt[m] else float("inf")

    report = {
        m: dict(
            attack=attack_cnt[m],
            budget=budget[m],
            protected=protected_cnt[m],
            benign=used[m],
            capped=capped[m],
            ratio=ratio(m),
        )
        for m in sorted(MARKERS)
    }
    return cfp_benign + admitted, n_hn, len(admitted) - n_hn, report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-file", default="data/train_full.jsonl")
    ap.add_argument("--hardneg-glob", required=True)
    ap.add_argument(
        "--extra-hardneg", default=None, help="extra hard-neg glob (e.g. orchestrator shards)"
    )
    ap.add_argument(
        "--cfp-glob", default=None, help="counterfactual PAIR shards (routed by own label)"
    )
    ap.add_argument("--cfp-dev-pairs", type=int, default=400, help="whole pairs held out for dev")
    ap.add_argument("--cfp-dev-out", default="data/cfp_dev.jsonl")
    ap.add_argument(
        "--oversample", type=int, default=1, help="hard-neg oversample factor (v2 used 2)"
    )
    ap.add_argument(
        "--balance-markers",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="cap benign rows per trigger marker so the marker carries no label "
        "information; --no-balance-markers reproduces the unbalanced build for ablation",
    )
    ap.add_argument(
        "--marker-tolerance",
        type=float,
        default=1.25,
        help="max benign:attack row ratio allowed per marker",
    )
    ap.add_argument("--eval-slice", default="eval/adversarial_slice.jsonl")
    ap.add_argument("--out", default="data/train_v3.jsonl")
    ap.add_argument("--seed", type=int, default=20260716)
    args = ap.parse_args()
    if args.oversample < 1:
        raise SystemExit("FATAL: --oversample must be >= 1")
    if args.marker_tolerance < 1.0:
        raise SystemExit(
            "FATAL: --marker-tolerance must be >= 1.0; below 1.0 the cap would start "
            "dropping benigns a marker's own attack rows already balance."
        )
    rng = random.Random(args.seed)

    # The held-out slice is decontaminated out of every candidate pool BEFORE sampling; the gate at
    # the end is the backstop that proves none survived. train_full ships with a verbatim copy of
    # advslice:control_attack:001, so filtering here (not just failing) is what makes v3 buildable.
    ev = {norm(json.loads(l)["text"]) for l in open(args.eval_slice) if l.strip()}

    base = [json.loads(l) for l in open(args.train_file) if l.strip()]
    base = [r for r in base if r.get("split") != "heldout"]
    base_contam = [r for r in base if norm(r["text"]) in ev]
    if base_contam:
        print(f"DECONTAM: dropped {len(base_contam)} base row(s) colliding with {args.eval_slice}:")
        for r in base_contam:
            print(f"  - {r.get('id')} (label={r.get('label')}, {r.get('source')})")
    base = [r for r in base if norm(r["text"]) not in ev]
    attack = [r for r in base if int(r["label"]) == 1]
    obenign = [r for r in base if int(r["label"]) == 0]
    base_seen = {norm(r["text"]) for r in base}

    # ---- counterfactual pairs: split whole pairs into dev/train, then route arms by own label ----
    cfp_attack, cfp_benign, dev_rows = [], [], []
    pstats, n_train_pairs, dropped_dup, dropped_contam = {}, 0, 0, 0
    if args.cfp_glob:
        pairs, pstats = load_pairs(args.cfp_glob)

        # Pair-level dedup: if ANY arm's text is already claimed, drop the WHOLE pair. Deduping arms
        # independently (as v2 does for hard-negs) would silently orphan the surviving arm.
        claimed = set(base_seen)
        kept = []
        for pid in sorted(pairs):  # sort => deterministic regardless of shard read order
            arms = pairs[pid]
            texts = [norm(a["text"]) for a in arms]
            if any(t in ev for t in texts):  # a pair touching held-out text is dropped WHOLE
                dropped_contam += 1
                continue
            if any(t in claimed for t in texts) or len(set(texts)) != len(texts):
                dropped_dup += 1
                continue
            claimed.update(texts)
            kept.append(pid)

        rng.shuffle(kept)  # shuffles PAIR IDS, never rows: arms cannot be separated by this
        n_dev = min(args.cfp_dev_pairs, len(kept))
        if n_dev < args.cfp_dev_pairs:
            print(
                f"WARN: only {len(kept)} usable pairs; dev takes {n_dev} of {args.cfp_dev_pairs} requested",
                file=sys.stderr,
            )
        # kept in LIST order, never a set: set iteration order of str varies per process under hash
        # randomization, which would make cfp_dev.jsonl non-reproducible across runs at one seed.
        dev_ids, train_ids = kept[:n_dev], kept[n_dev:]
        n_train_pairs = len(train_ids)

        for pid in dev_ids:
            for a in pairs[pid]:
                r = dict(a)
                r["split"] = "dev"
                dev_rows.append({k: r.get(k) for k in DEV_SCHEMA})
        for pid in train_ids:
            for a in pairs[pid]:
                row = {k: a.get(k) for k in SCHEMA}  # class/pair_id stripped from TRAIN only
                (cfp_attack if int(a["label"]) == 1 else cfp_benign).append(row)

        cfp_train_texts = {norm(r["text"]) for r in cfp_attack + cfp_benign}
        dev_texts = {norm(r["text"]) for r in dev_rows}
    else:
        cfp_train_texts, dev_texts = set(), set()

    # ---- hard-negs (label 0 only), deduped by normalized text against base, cfp and each other ----
    hn, _ = load_glob(args.hardneg_glob)
    if args.extra_hardneg:
        hn += load_glob(args.extra_hardneg)[0]
    seen = base_seen | cfp_train_texts | dev_texts | ev
    uniq_hn, hn_seen = [], set()
    for r in hn:
        n = norm(r["text"])
        if n in seen or n in hn_seen or len(r["text"]) < 20:
            continue
        if int(r["label"]) != 0:
            raise SystemExit(
                f"FATAL: hard-neg pool row {r.get('id')} has label={r['label']}; "
                "hard-negs must be label=0. Pair data belongs in --cfp-glob."
            )
        hn_seen.add(n)
        uniq_hn.append({k: r.get(k) for k in SCHEMA})
    rng.shuffle(uniq_hn)

    # ---- balance to ~50/50 by LABEL. Pair arms are protected: they are balance-neutral (each pair
    # adds one row per side) and are never truncated. Fill/trim originals, then hard-negs. ----
    attack_final = attack + cfp_attack
    n_attack = len(attack_final)
    hn_over = uniq_hn * args.oversample
    protected = len(cfp_benign)
    room = n_attack - protected
    if room < 0:
        raise SystemExit(
            f"FATAL: {protected} cfp benign arms exceed the {n_attack}-row attack side; "
            "cannot balance without splitting pairs."
        )
    mreport = {}
    if args.balance_markers:
        # trims/skips unpaired benigns only; cfp_benign is passed for BUDGET accounting, never as a
        # candidate. The pool assertion below proves no pair arm could reach this list.
        benign_final, n_hn_used, n_orig_used, mreport = fill_benign_balanced(
            hn_over, obenign, cfp_benign, attack_final, room, args.marker_tolerance, rng
        )
    elif len(hn_over) >= room:
        hn_used = hn_over[:room]  # trims hard-negs, never pair arms
        n_hn_used, n_orig_used = len(hn_used), 0
        benign_final = cfp_benign + hn_used
    else:
        hn_used = hn_over
        n_hn_used, n_orig_used = len(hn_used), room - len(hn_over)
        rng.shuffle(obenign)
        benign_final = cfp_benign + hn_used + obenign[:n_orig_used]
    if len(benign_final) < n_attack:
        print(
            f"WARN: benign side is {len(benign_final)} rows vs {n_attack} attack -- the marker "
            f"caps exhausted both benign pools; label balance is "
            f"{100 * len(benign_final) / (len(benign_final) + n_attack):.1f}% benign, not 50%.",
            file=sys.stderr,
        )

    final = attack_final + benign_final
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

    # ---- contamination gate: nothing in train OR dev may collide with the held-out slice ----
    hits = [r for r in out if norm(r["text"]) in ev] + [
        r for r in dev_rows if norm(r["text"]) in ev
    ]
    if hits:
        for r in hits[:10]:
            print(f"  COLLISION {r.get('id')} :: {r['text'][:90]!r}", file=sys.stderr)
        raise SystemExit(
            f"FATAL: {len(hits)} row(s) collide with {args.eval_slice}; refusing to write."
        )

    # ---- pair atomicity, asserted against the rows actually EMITTED (arm ids), not against the
    # grouping the logic above already trusts. Train rows have pair_id stripped, so arms are matched
    # back by their unique arm id. ----
    dev_by_pid = defaultdict(int)
    if args.cfp_glob:
        want = {pid: {a["id"] for a in arms} for pid, arms in pairs.items()}
        emitted = {r["id"] for r in out}  # the final shuffled train rows

        # The balancer drops rows. Prove mechanically that no pair arm was ever ELIGIBLE to be one
        # of them: the downsampling pool must be disjoint from every arm id, dev and train alike.
        arm_ids = {a["id"] for arms in pairs.values() for a in arms}
        pool_ids = {r.get("id") for r in hn_over} | {r.get("id") for r in obenign}
        if arm_ids & pool_ids:
            raise SystemExit(
                f"FATAL: {len(arm_ids & pool_ids)} pair arm(s) entered the benign "
                "downsampling pool; the balancer could drop one and orphan its twin."
            )
        for pid in train_ids:
            missing = want[pid] - emitted
            if missing:
                raise SystemExit(f"FATAL: train pair {pid} lost arm(s) {sorted(missing)}")
        dev_ids_by_pid = defaultdict(set)
        for r in dev_rows:
            dev_ids_by_pid[r["pair_id"]].add(r["id"])
            dev_by_pid[r["pair_id"]] += 1
        for pid, got in dev_ids_by_pid.items():
            if got != want[pid]:
                raise SystemExit(f"FATAL: dev pair {pid} lost arm(s) {sorted(want[pid] - got)}")
        if set(train_ids) & set(dev_ids_by_pid):
            raise SystemExit("FATAL: train/dev pair_id sets overlap")
        if emitted & {r["id"] for r in dev_rows}:
            raise SystemExit("FATAL: a dev arm id also appears in the train file")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    if args.cfp_glob:
        Path(args.cfp_dev_out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.cfp_dev_out, "w") as f:
            for r in dev_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    nb = sum(1 for r in out if int(r["label"]) == 0)
    print(f"WROTE {len(out)} -> {args.out}")
    print(f"  attack={n_attack} benign={nb} ({100 * nb / len(out):.0f}% benign)")
    print(
        f"  unique hard-negs={len(uniq_hn)} x{args.oversample}={len(hn_over)} "
        f"-> {n_hn_used} used + {n_orig_used} original benigns"
    )
    if args.balance_markers:
        print(
            f"  marker balance (tolerance {args.marker_tolerance}x benign:attack; "
            f"'capped' = unpaired benigns dropped):"
        )
        print(
            f"    {'marker':<16} {'attack':>7} {'benign':>7} {'ratio':>7} {'budget':>7} "
            f"{'paired':>7} {'capped':>7}"
        )
        over = []
        for m, s in mreport.items():
            flag = ""
            if s["ratio"] > args.marker_tolerance + 1e-9:
                over.append(m)
                flag = " <-- OVER TOLERANCE"
            print(
                f"    {m:<16} {s['attack']:>7} {s['benign']:>7} {s['ratio']:>7.2f} "
                f"{s['budget']:>7} {s['protected']:>7} {s['capped']:>7}{flag}"
            )
        if over:
            print(
                f"    NOT within tolerance: {', '.join(over)} -- every eligible unpaired benign "
                "was dropped and the ratio is still over. More pairs are the only remaining lever."
            )
        print(
            "    dropping trigger-dense benigns is an OVER-DEFENSE risk by construction; "
            "'capped' above is what to attribute any regression to."
        )
    if args.cfp_glob:
        print(
            f"  cfp: {pstats['rows']} rows / {pstats['seen_pairs']} pair_ids seen; "
            f"usable={pstats['usable']} dropped_incomplete={pstats['dropped_incomplete']} "
            f"dropped_dup={dropped_dup} dropped_contam={dropped_contam} "
            f"partial_lines={pstats['partial_lines']}"
        )
        print(
            f"  cfp: train_pairs={n_train_pairs} ({len(cfp_attack)} attack + {len(cfp_benign)} benign arms) "
            f"dev_pairs={len(dev_by_pid)} ({len(dev_rows)} rows) -> {args.cfp_dev_out}"
        )
    print(f"  contamination vs {args.eval_slice}: 0 collisions")


if __name__ == "__main__":
    main()
