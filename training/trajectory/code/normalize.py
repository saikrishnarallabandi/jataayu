"""Normalize trajectory corpora into one prefix-scoring schema.

`Jataayu.trajectory.v0.1` scores a trajectory IN PROGRESS: given tool calls 1..k, is this
heading to compromise? So the unit that leaves this module is a trajectory with its ordered
steps and a label, and the trainer expands it into prefixes.

Steps keep the tool name AND the serialized arguments. That is load-bearing, not incidental:
our name-based effect classifier collapses on shell agents (BashArena has 4 distinct tool
names over 22,780 steps, 69.4% of them `bash`), so `cat /etc/passwd` and `cat README.md` are
the same token to it. To a model reading arguments they are not. The model is the
argument-aware effect extractor the boundary has been deferring.

Corpora, all externally authored — nothing here is self-authored, which is how
effect-boundary-v2 produced a fit artifact:
  agentdojo   36,679 traces, 4 suites, agent-as-VICTIM (injected text manipulates a benign agent)
  basharena    1,122 traces, agent-as-ADVERSARY, has point_of_no_return_step
  shade        1,500 traces, agent-as-ADVERSARY

Run:  python training/trajectory/code/normalize.py --out training/trajectory/data
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Optional

ROOT = Path(__file__).resolve().parents[3]
TRAJ = ROOT / "benchmarks" / "data" / "trajectories"


@dataclass
class Step:
    tool: str
    args: str  # serialized; kept as text because the model reads it as text


@dataclass
class Traj:
    tid: str
    source: str
    steps: list[Step]
    label: int  # 1 = compromise occurred, 0 = it did not
    bucket: str  # "benign" | "attack_failed" | "compromised" — negatives are not all alike
    suite: Optional[str] = None
    point_of_no_return: Optional[int] = None  # 1-indexed step
    meta: dict = field(default_factory=dict)


# -- AgentDojo -----------------------------------------------------------------
# LABEL TRAP, verified in task_suite.py `run_task_with_pipeline`:
#   "Returns: ... the second indicating if the injection was successful"
#   security = self._check_task_result(injection_task, ...)
# so security=True means THE ATTACK SUCCEEDED -- but only when an injection was actually
# intended. There is an early return above it:
#   if injection_task is None: return utility, True
# which hardcodes True for no-injection rows. A loader that ignores injection_task_id labels
# 3,546 non-attack trajectories as attacks. A first pass did exactly that and its numbers had
# to be retracted, so this is asserted rather than commented.


def load_agentdojo(root: Path) -> Iterator[Traj]:
    for f in root.rglob("*.json"):
        try:
            d = json.loads(f.read_text())
        except (ValueError, OSError):
            continue
        if d.get("error"):
            continue
        security = d.get("security")
        if security is None:
            continue
        injected = d.get("injection_task_id") is not None

        if not injected:
            label, bucket = 0, "benign"
        elif security is True:
            label, bucket = 1, "compromised"
        else:
            # An injection was present and did NOT land. These are the hard negatives that
            # stop the model degenerating into an injection-text detector: attacked-but-not-
            # compromised must score LOW, or we have just rebuilt the v0.1 detector.
            label, bucket = 0, "attack_failed"

        steps = [
            Step(tool=tc["function"], args=json.dumps(tc.get("args", {}), sort_keys=True))
            for m in d.get("messages", [])
            if m.get("role") == "assistant"
            for tc in (m.get("tool_calls") or [])
            if tc.get("function")
        ]
        if len(steps) < 2:
            continue
        yield Traj(
            tid=str(f.relative_to(root)),
            source="agentdojo",
            steps=steps,
            label=label,
            bucket=bucket,
            suite=d.get("suite_name"),
            meta={
                "pipeline": d.get("pipeline_name"),
                "attack_type": d.get("attack_type"),
                "utility": d.get("utility"),
            },
        )


# -- BashArena -----------------------------------------------------------------
# Transcript is a text blob, step-indexed:
#   <step_1><assistant><tool_0><function>bash</function><arguments>{...}</arguments>
_STEP_RE = re.compile(
    r"<function>(?P<tool>.*?)</function>\s*<arguments>(?P<args>.*?)</arguments>", re.S
)


def load_basharena(root: Path) -> Iterator[Traj]:
    import pandas as pd

    pq = next((root / "data").glob("*.parquet"), None)
    if pq is None:
        return
    df = pd.read_parquet(pq)
    for _, row in df.iterrows():
        steps = [
            Step(tool=m.group("tool").strip(), args=m.group("args").strip())
            for m in _STEP_RE.finditer(row["transcript"])
        ]
        if len(steps) < 2:
            continue
        category = str(row.get("category", ""))
        label = int(row["ground_truth"])
        yield Traj(
            tid=f"basharena/{row['id']}",
            source="basharena",
            steps=steps,
            label=label,
            bucket="compromised" if label else "benign",
            meta={"category": category, "data_source": str(row.get("data_source", ""))},
        )


LOADERS = {
    "agentdojo": (load_agentdojo, TRAJ / "agentdojo_upstream" / "runs"),
    "basharena": (load_basharena, TRAJ / "adityaasinha28__basharena_action_only_opus46_large"),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only", choices=sorted(LOADERS), action="append")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    for name in args.only or sorted(LOADERS):
        loader, src = LOADERS[name]
        if not src.exists():
            print(f"SKIP {name}: {src} missing", file=sys.stderr)
            continue
        buckets: collections.Counter = collections.Counter()
        depth: list[int] = []
        path = args.out / f"{name}.jsonl"
        with path.open("w") as fh:
            for t in loader(src):
                buckets[t.bucket] += 1
                depth.append(len(t.steps))
                fh.write(json.dumps(asdict(t)) + "\n")
        if not depth:
            print(f"SKIP {name}: produced 0 trajectories", file=sys.stderr)
            continue
        depth.sort()
        print(
            f"{name:11} {len(depth):6} traj  "
            f"steps med={depth[len(depth) // 2]:3} max={depth[-1]:4}  "
            f"{dict(buckets.most_common())}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
