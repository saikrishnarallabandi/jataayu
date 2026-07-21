"""Build train / val / test splits for the prefix risk scorer.

The holdout discipline is the strictest of the options considered, on purpose (Sai, 2026-07-21):

  TEST   BashArena, entirely untouched      the only agent-as-ADVERSARY corpus. An untouched
                                            holdout here is the evidence we generalize to the
                                            threat model that motivated the work, and it is the
                                            claim a reviewer attacks first.
  TEST   AgentDojo `banking` suite          cross-suite generalization. Banking is the most
                                            semantically distant from workspace/travel/slack, so
                                            it is the harder direction to transfer.
  TRAIN  AgentDojo workspace/travel/slack
  VAL    a slice of TRAIN held out BY USER TASK, never at random.

The by-user-task rule matters. Each (user_task, injection_task) pair recurs across 27 pipelines
-- 27 near-identical trajectories differing only by the model that produced them. A random
split puts siblings on both sides and validation stops measuring generalization: it measures
memorization of the task. Suites are already task-disjoint, so the suite holdout is clean by
construction; only the train/val boundary needs this.

Run:  python training/trajectory/code/split.py --data training/trajectory/data
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

HOLDOUT_SUITE = "banking"
VAL_FRACTION = 0.12


def _task_key(t: dict) -> str:
    """The (suite, user_task) identity a trajectory belongs to, from its tid path."""
    parts = Path(t["tid"]).parts
    # pipeline/suite/user_task/attack/injection.json
    return "/".join(parts[1:3]) if len(parts) >= 3 else t["tid"]


def _assign(key: str) -> str:
    """Deterministic hash bucketing — stable across runs and machines, unlike random.shuffle
    with an ambient seed, so a re-run cannot silently move a task across the boundary."""
    h = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "val" if h < VAL_FRACTION else "train"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    args = ap.parse_args()

    splits: dict[str, list[dict]] = collections.defaultdict(list)

    ad = args.data / "agentdojo.jsonl"
    for line in ad.open():
        t = json.loads(line)
        if t["suite"] == HOLDOUT_SUITE:
            splits["test_agentdojo_banking"].append(t)
        else:
            splits[_assign(_task_key(t))].append(t)

    ba = args.data / "basharena.jsonl"
    if ba.exists():
        splits["test_basharena"] = [json.loads(line) for line in ba.open()]

    # A task must never straddle train and val, or val is measuring memorization.
    train_tasks = {_task_key(t) for t in splits["train"]}
    val_tasks = {_task_key(t) for t in splits["val"]}
    overlap = train_tasks & val_tasks
    assert not overlap, f"{len(overlap)} tasks straddle train/val: {sorted(overlap)[:5]}"

    # And no AgentDojo suite may straddle train and test.
    train_suites = {t["suite"] for t in splits["train"]} | {t["suite"] for t in splits["val"]}
    assert HOLDOUT_SUITE not in train_suites, f"{HOLDOUT_SUITE} leaked into train/val"

    out = args.data / "splits"
    out.mkdir(exist_ok=True)
    for name, rows in splits.items():
        with (out / f"{name}.jsonl").open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        b = collections.Counter(r["bucket"] for r in rows)
        pos = sum(1 for r in rows if r["label"] == 1)
        print(
            f"{name:26} {len(rows):6} traj  pos={pos:5} ({pos / len(rows):5.1%})  "
            f"{dict(b.most_common())}"
        )
    print(f"\ntasks: train={len(train_tasks)} val={len(val_tasks)} disjoint=OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
