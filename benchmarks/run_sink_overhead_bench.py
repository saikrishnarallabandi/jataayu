#!/usr/bin/env python3
"""
Jataayu decision-sink overhead — what telemetry costs on the authorization hot path.

`EffectBoundary.preview()` builds a decision record only when a sink is installed, and
`emit_decision` hands the sink a deep copy so it cannot mutate live decision state. That is a
per-action cost on the one path that runs before every tool call, so it is worth a number.

Three arms, same actions:
  no sink                 no record built; preview() resolves the sink to None and moves on
  trivial sink            record built + deep-copied + delivered
  trivial sink + content  as above, with the caller's params dict in the copy

Reports WARM per-call latency (a warm-up pass is timed and discarded), because this measures a
fixed overhead rather than a corpus, and cold numbers here are dominated by import/compile.

Usage:
  python benchmarks/run_sink_overhead_bench.py
  python benchmarks/run_sink_overhead_bench.py --reps 20 --json
  python benchmarks/run_sink_overhead_bench.py --repeat 6      # median-of-6 latency
"""

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from bench_latency import median_of_runs, summarize  # noqa: E402

from jataayu.core.audit import set_decision_sink  # noqa: E402
from jataayu.guards.effect_boundary import EffectBoundary  # noqa: E402

OUT_DIR = HERE / "results"
OUT_DIR.mkdir(exist_ok=True)


def load_actions(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            r = json.loads(line)
            rows.append((r["tool"], r.get("params", {})))
    return rows


def measure(boundary, actions, reps, repeat=1):
    for tool, params in actions:  # warm-up, discarded
        boundary.preview(tool, params)
    runs = []
    for _ in range(repeat):
        lat = []
        for _ in range(reps):
            for tool, params in actions:
                t0 = time.perf_counter()
                boundary.preview(tool, params)
                lat.append((time.perf_counter() - t0) * 1000)
        runs.append(summarize(lat))
    return {"n_calls": len(lat), **median_of_runs(runs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(HERE / "data" / "effect_boundary_v1.jsonl"))
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default=str(OUT_DIR / "sink_overhead.json"))
    ap.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="repeat the whole measurement N times per arm and report the "
        "median of the per-run statistics",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")

    actions = load_actions(args.dataset)
    over = f" x {args.repeat} runs" if args.repeat > 1 else ""
    print(
        f"[sink-overhead] {len(actions)} actions x {args.reps} reps "
        f"= {len(actions) * args.reps} calls per arm{over}"
    )

    delivered = []
    arms = {}
    try:
        set_decision_sink(None)
        arms["no_sink"] = measure(EffectBoundary(), actions, args.reps, args.repeat)

        set_decision_sink(lambda record: delivered.append(record["decision"]))
        arms["trivial_sink"] = measure(EffectBoundary(), actions, args.reps, args.repeat)
        if not delivered:
            raise SystemExit("sink never fired — the overhead number would be meaningless")

        before = len(delivered)
        set_decision_sink(lambda record: delivered.append(record["decision"]), capture_content=True)
        arms["trivial_sink_capture_content"] = measure(
            EffectBoundary(), actions, args.reps, args.repeat
        )
        if len(delivered) == before:
            raise SystemExit("sink stopped firing under capture_content")
    finally:
        # A module-level sink outlives this process only in-process, but leaving one installed
        # would poison any later import in the same interpreter (e.g. a REPL or a test runner).
        set_decision_sink(None)

    base = arms["no_sink"]["mean"]
    for name, arm in arms.items():
        arm["overhead_vs_no_sink_ms"] = round(arm["mean"] - base, 4)
        arm["ratio_vs_no_sink"] = round(arm["mean"] / base, 3) if base else None

    result = {
        "benchmark": "Jataayu decision-sink overhead (effect boundary preview)",
        "api": "EffectBoundary.preview + core.audit.emit_decision (deterministic, no LLM)",
        "dataset": args.dataset,
        "reps": args.reps,
        "repeat": args.repeat,
        "note": "warm per-call latency; one warm-up pass timed and discarded",
        "arms": arms,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))

    print(
        f"\n{'arm':32} {'mean':>8} {'p50':>8} {'p99':>8} {'vs none':>9}"
        f"{f'   (median of {args.repeat} runs)' if args.repeat > 1 else ''}"
    )
    for name, arm in arms.items():
        print(
            f"{name:32} {arm['mean']:>8.4f} {arm['p50']:>8.4f} {arm['p99']:>8.4f} "
            f"{arm['ratio_vs_no_sink']:>8.2f}x"
        )
    print(f"\nwrote {args.out}")

    if args.json:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
