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
"""
import argparse
import json
import statistics as st
import time
from pathlib import Path

from jataayu.core.audit import set_decision_sink
from jataayu.guards.effect_boundary import EffectBoundary

HERE = Path(__file__).parent
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


def measure(boundary, actions, reps):
    for tool, params in actions:  # warm-up, discarded
        boundary.preview(tool, params)
    lat = []
    for _ in range(reps):
        for tool, params in actions:
            t0 = time.perf_counter()
            boundary.preview(tool, params)
            lat.append((time.perf_counter() - t0) * 1000)
    s = sorted(lat)
    return {
        "n_calls": len(lat),
        "mean": round(st.mean(lat), 4),
        "p50": round(st.median(lat), 4),
        "p99": round(s[max(0, int(len(s) * 0.99) - 1)], 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(HERE / "data" / "effect_boundary_v1.jsonl"))
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default=str(OUT_DIR / "sink_overhead.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    actions = load_actions(args.dataset)
    print(f"[sink-overhead] {len(actions)} actions x {args.reps} reps "
          f"= {len(actions) * args.reps} calls per arm")

    delivered = []
    arms = {}
    try:
        set_decision_sink(None)
        arms["no_sink"] = measure(EffectBoundary(), actions, args.reps)

        set_decision_sink(lambda record: delivered.append(record["decision"]))
        arms["trivial_sink"] = measure(EffectBoundary(), actions, args.reps)
        if not delivered:
            raise SystemExit("sink never fired — the overhead number would be meaningless")

        before = len(delivered)
        set_decision_sink(lambda record: delivered.append(record["decision"]),
                          capture_content=True)
        arms["trivial_sink_capture_content"] = measure(EffectBoundary(), actions, args.reps)
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
        "note": "warm per-call latency; one warm-up pass timed and discarded",
        "arms": arms,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))

    print(f"\n{'arm':32} {'mean':>8} {'p50':>8} {'p99':>8} {'vs none':>9}")
    for name, arm in arms.items():
        print(f"{name:32} {arm['mean']:>8.4f} {arm['p50']:>8.4f} {arm['p99']:>8.4f} "
              f"{arm['ratio_vs_no_sink']:>8.2f}x")
    print(f"\nwrote {args.out}")

    if args.json:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
