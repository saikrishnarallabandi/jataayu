"""Report what each authority-framing surface marker teaches about the label.

v0.1 learned "SYSTEM: => BENIGN" (112:1 benign in the v2 mix) and shipped a one-line evasion. The
acceptance criterion for a replacement build is that these markers carry NO label information:
attack and benign counts near 1:1, i.e. P(attack|marker) near the corpus base rate.

This is deliberately a SEPARATE list from build_train_v3.MARKERS. That list is derived from the
pair generator and is what the builder optimizes; auditing with it only proves the builder did
what it was told. These are the patterns the blind spot was measured with, so they can catch a
marker the builder never balanced.

Run:  eval/.venv-hf/bin/python code/authority_ratio.py data/train_v3_clean.jsonl [more files...]
Exit 1 if any marker is worse than --max-ratio in either direction.
"""

import argparse
import json
import re
import sys

PATTERNS = {
    "system:": r"system\s*:",
    "developer mode": r"developer\s+mode",
    "you are now": r"you are now",
    "ignore (all) previous": r"ignore\s+(all\s+)?previous",
}


def audit(path):
    att = {k: 0 for k in PATTERNS}
    ben = {k: 0 for k in PATTERNS}
    n_att = n_ben = 0
    pats = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            lab = int(r["label"])
            if lab == 1:
                n_att += 1
            else:
                n_ben += 1
            t = r.get("text") or ""
            for k, c in pats.items():
                if c.search(t):
                    (att if lab == 1 else ben)[k] += 1
    return att, ben, n_att, n_ben


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument(
        "--max-ratio",
        type=float,
        default=3.0,
        help="fail if benign:attack or attack:benign exceeds this for any marker",
    )
    args = ap.parse_args()

    worst = {}
    for path in args.files:
        att, ben, n_att, n_ben = audit(path)
        total = n_att + n_ben
        if not total:
            print(f"\n=== {path}: EMPTY")
            continue
        base = n_att / total
        print(f"\n=== {path}")
        print(f"    rows={total} attack={n_att} benign={n_ben} base rate P(attack)={base:.3f}")
        print(
            f"    {'marker':<24} {'attack':>8} {'benign':>8} {'ben:att':>10} "
            f"{'P(att|marker)':>14} {'verdict':>10}"
        )
        bad = []
        for k in PATTERNS:
            a, b = att[k], ben[k]
            if a + b == 0:
                print(f"    {k:<24} {'-':>8} {'-':>8} {'absent':>10} {'-':>14} {'-':>10}")
                continue
            # A marker with rows on only one side is maximally informative, not neutral: it is the
            # exact failure mode (112:1) this check exists to catch, so it is inf, never skipped.
            ratio = b / a if a else float("inf")
            skew = max(ratio, 1 / ratio) if ratio else float("inf")
            ok = skew <= args.max_ratio
            if not ok:
                bad.append(k)
            rs = "inf" if ratio == float("inf") else f"{ratio:.2f}"
            print(
                f"    {k:<24} {a:>8} {b:>8} {rs:>10} {a / (a + b):>14.3f} "
                f"{'OK' if ok else 'FAIL':>10}"
            )
        worst[path] = bad
        if bad:
            print(f"    OVER {args.max_ratio}:1 -> {', '.join(bad)}")

    fails = {p: b for p, b in worst.items() if b}
    print(f"\nVERDICT: {'PASS' if not fails else 'FAIL ' + json.dumps(fails)}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
