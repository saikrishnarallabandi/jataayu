#!/usr/bin/env python3
"""
Jataayu input-normalization ablation — what the normalized views actually buy.

Backs the README's normalization claim with a measured number instead of an asserted one.
Takes the attack rows a corpus, scores them clean, then re-scores the ones that were caught
after each evasion transform, with `InboundGuard(normalize=...)` flipped:

  EVASION RATE = of the attack rows caught in CLEAN form at the MEDIUM operating point,
                 the fraction NOT caught after the transform.

Anchoring on the clean-caught subset is the point: rows the detector never caught cannot be
"evaded", and pooling them in would dilute the rate toward whatever the base recall is.

Transforms are `run_injection_bench.py`'s, so the numbers line up with that runner's
`robustness` block (which reports the normalize=True side only).

Usage:
  python benchmarks/run_normalization_ablation.py
  python benchmarks/run_normalization_ablation.py --dataset deepset/prompt-injections \
      --out benchmarks/results/normalization_ablation.json --json
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from run_injection_bench import TRANSFORMS, load_binary  # noqa: E402

from jataayu.guards.inbound import InboundGuard  # noqa: E402

OUT_DIR = HERE / "results"
OUT_DIR.mkdir(exist_ok=True)

MEDIUM = 0.45  # the MEDIUM operating point, same as run_injection_bench.py


def measure_arm(normalize, pos, surface):
    """Evasion rates for one `normalize=` arm, anchored on the clean-caught subset."""
    guard = InboundGuard(use_llm=False, normalize=normalize)
    caught = [t for t in pos if guard.check(t, surface=surface).risk_score >= MEDIUM]
    if not caught:
        raise SystemExit(f"nothing caught at MEDIUM with normalize={normalize}; "
                         "evasion rate is undefined")
    arm = {"baseline_caught_at_MEDIUM": len(caught), "transforms": {}}
    for name, transform in TRANSFORMS.items():
        still = sum(1 for t in caught
                    if guard.check(transform(t), surface=surface).risk_score >= MEDIUM)
        arm["transforms"][name] = {
            "still_caught": still,
            "evasion_rate": round(1 - still / len(caught), 4),
        }
    return arm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="deepset/prompt-injections")
    ap.add_argument("--surface", default="unknown")
    ap.add_argument("--out", default=str(OUT_DIR / "normalization_ablation.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    pos = [t for t, y in load_binary(args.dataset) if y == 1]
    if not pos:
        raise SystemExit(f"no attack rows in {args.dataset}")
    print(f"[normalization-ablation] {args.dataset} | attack rows={len(pos)} "
          f"| surface={args.surface} | threshold=MEDIUM({MEDIUM})")

    result = {
        "benchmark": "Jataayu input-normalization ablation",
        "api": "InboundGuard(normalize=True|False).check (fast path, no LLM)",
        "dataset": args.dataset,
        "surface": args.surface,
        "threshold": MEDIUM,
        "n_attack_rows": len(pos),
        "arms": {},
    }

    for normalize in (True, False):
        result["arms"][f"normalize={normalize}"] = measure_arm(normalize, pos, args.surface)

    Path(args.out).write_text(json.dumps(result, indent=2))

    on, off = result["arms"]["normalize=True"], result["arms"]["normalize=False"]
    print(f"\n{'transform':14} {'evasion off':>12} {'evasion on':>12}")
    for name in TRANSFORMS:
        print(f"{name:14} {off['transforms'][name]['evasion_rate']:>12.4f} "
              f"{on['transforms'][name]['evasion_rate']:>12.4f}")
    print(f"\nclean-caught baseline: normalize=True {on['baseline_caught_at_MEDIUM']}, "
          f"normalize=False {off['baseline_caught_at_MEDIUM']}")
    print(f"wrote {args.out}")

    if args.json:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
