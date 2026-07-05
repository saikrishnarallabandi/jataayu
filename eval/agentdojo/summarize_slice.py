"""Per-task utility/ASR summary for an AgentDojo slice run.

The aggregate report JSON (run_agentdojo.py --out) only stores suite-level rows.
AgentDojo persists per-trace `utility`/`security` verdicts into each trajectory
file under the logdir, so this reads those directly and prints a per-user-task
baseline-vs-jataayu breakdown with deltas.

Usage:
    python eval/agentdojo/summarize_slice.py runs/agentdojo/slice_<TS>
    python eval/agentdojo/summarize_slice.py            # newest slice_* dir
"""
from __future__ import annotations

import collections
import glob
import json
import sys
from pathlib import Path


def _variant(pipeline_name: str) -> str:
    return "jataayu" if pipeline_name.startswith("jataayu") else "baseline"


def _utid(x: str) -> int:
    try:
        return int(x.split("_")[-1])
    except ValueError:
        return 1 << 30


def summarize(base: str) -> None:
    noatk: dict = collections.defaultdict(dict)          # ut -> {variant: utility}
    atk: dict = collections.defaultdict(lambda: collections.defaultdict(list))  # ut -> variant -> [(inj, util, sec)]

    for f in glob.glob(f"{base}/**/*.json", recursive=True):
        d = json.load(open(f))
        ut = d["user_task_id"]
        # skip injection-task utility-calibration runs (they reuse an injection id as user_task_id)
        if ut is None or str(ut).startswith("injection_task"):
            continue
        v = _variant(d["pipeline_name"])
        inj = d["injection_task_id"]
        if inj is None and d["attack_type"] is None:
            noatk[ut][v] = d["utility"]
        elif inj is not None:
            atk[ut][v].append((inj, d["utility"], d["security"]))

    uts = sorted(set(list(noatk) + list(atk)), key=_utid)

    def under_attack(ut, v):
        r = atk[ut].get(v, [])
        if not r:
            return None, None, 0
        util = sum(1 for _, u, _ in r if u) / len(r)
        asr = sum(1 for _, _, s in r if s) / len(r)   # security==True means injected goal achieved
        return util, asr, len(r)

    def fmt(x):
        return f"{x:.2f}" if x is not None else "  - "

    print(f"slice: {base}\n")
    hdr = (f"{'user_task':<13} | {'no-atk util':^15} | {'under-atk util':^15} | "
           f"{'ASR (n)':^22}")
    print(hdr)
    print("-" * len(hdr))
    print(f"{'':<13} | {'base':>6} {'jat':>6} | {'base':>6} {'jat':>6} | {'base':>9} {'jat':>9}")
    print("-" * len(hdr))

    bu_all, ju_all, ba_all, ja_all = [], [], [], []
    for ut in uts:
        nb, nj = noatk[ut].get("baseline"), noatk[ut].get("jataayu")
        bu, ba, bn = under_attack(ut, "baseline")
        ju, ja, jn = under_attack(ut, "jataayu")
        if bn:
            bu_all.append(bu); ba_all.append(ba)
        if jn:
            ju_all.append(ju); ja_all.append(ja)
        print(f"{ut:<13} | {fmt(nb):>6} {fmt(nj):>6} | {fmt(bu):>6} {fmt(ju):>6} | "
              f"{fmt(ba):>6}({bn:>2}) {fmt(ja):>5}({jn:>2})")

    print("-" * len(hdr))
    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")
    print(f"{'AGG':<13} | {'':>6} {'':>6} | {mean(bu_all):>6.2f} {mean(ju_all):>6.2f} | "
          f"{mean(ba_all):>9.2f} {mean(ja_all):>9.2f}")

    print("\nDELTAS (jataayu - baseline):")
    for ut in uts:
        bu, ba, bn = under_attack(ut, "baseline")
        ju, ja, jn = under_attack(ut, "jataayu")
        if not (bn and jn):
            continue
        tags = []
        if ja < ba:
            tags.append(f"ASR {ba:.2f}->{ja:.2f} (blocked {round((ba - ja) * bn)}/{bn})")
        if ju > bu:
            tags.append(f"util {bu:.2f}->{ju:.2f} (recovered)")
        print(f"  {ut}: " + ("; ".join(tags) if tags else "no change"))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        base = sys.argv[1]
    else:
        dirs = sorted(glob.glob("runs/agentdojo/slice_*"))
        if not dirs:
            print("no runs/agentdojo/slice_* directory found", file=sys.stderr)
            sys.exit(1)
        base = dirs[-1]
    if not Path(base).is_dir():
        print(f"not a directory: {base}", file=sys.stderr)
        sys.exit(1)
    summarize(base)
