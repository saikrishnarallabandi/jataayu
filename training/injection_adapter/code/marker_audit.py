"""Audit what a built training file teaches about each trigger marker.

The invariant v3 exists to enforce is NOT a row ratio -- it is that a marker carries no label
information: P(attack | marker) must sit at the corpus base rate (~0.5), so seeing "SYSTEM:" tells
the model nothing. The benign:attack ratio is only the proxy the builder can act on. This prints
both, per marker, for one or more files, so the proxy can never drift away from the thing it proxies
unnoticed.

Markers and matching come from build_train_v3 (which derives them from the pair generator's own
AUTH_MARKERS) -- never redefine them here, or the audit stops auditing the build.

Run:  python code/marker_audit.py data/train_v2.jsonl data/train_v3.jsonl
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_train_v3 import MARKERS, markers_in  # noqa: E402


def audit(path):
    att, ben = Counter(), Counter()
    n_att = n_ben = 0
    for line in Path(path).open():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        lab = int(r["label"])
        if lab == 1:
            n_att += 1
        else:
            n_ben += 1
        for m in markers_in(r["text"]):
            (att if lab == 1 else ben)[m] += 1
    return att, ben, n_att, n_ben


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    for path in args.files:
        att, ben, n_att, n_ben = audit(path)
        total = n_att + n_ben
        if not total:
            print(f"\n=== {path}: EMPTY")
            continue
        base = n_att / total
        print(f"\n=== {path}")
        print(f"    rows={total}  attack={n_att}  benign={n_ben}  base rate P(attack)={base:.3f}")
        print(
            f"    {'marker':<16} {'attack':>7} {'benign':>7} {'benign:attack':>14} "
            f"{'P(attack|marker)':>17} {'vs base':>9}"
        )
        for m in sorted(MARKERS):
            a, b = att[m], ben[m]
            if a + b == 0:
                print(f"    {m:<16} {'-':>7} {'-':>7} {'absent':>14} {'-':>17} {'-':>9}")
                continue
            ratio = f"{b / a:>13.2f}" if a else f"{'inf':>13}"
            p = a / (a + b)
            print(f"    {m:<16} {a:>7} {b:>7} {ratio:>14} {p:>17.3f} {p - base:>+9.3f}")


if __name__ == "__main__":
    main()
