"""Unrecognized-rate of the effect classifier over REAL tool names.

Issue #22. The classifier falls back to READ for a name it does not recognize, which is a
declared fail-open: `strict_unknown_tools` gates it, `recognized=False` rides on every
decision record, and the default is off because gating an unrecognized name is only viable
once unrecognized is the exception rather than the common case. This is the number that
says whether it is.

The corpus is deliberately NOT self-authored — it is every tool name appearing in AgentHarm
and InjecAgent, both externally written. A coverage number measured on names we invented
would measure our imagination, which is the effect-boundary-v2 mistake.

Run:  python benchmarks/run_effect_coverage.py
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jataayu.guards.effect_boundary import EffectBoundary  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
TARGET = 0.10  # issue #22's stated ceiling for flipping strict_unknown_tools on by default


def _agentharm_names() -> set[str]:
    names: set[str] = set()
    for f in (DATA / "agentharm").glob("*behaviors*.json"):
        raw = json.loads(f.read_text())
        items = raw["behaviors"] if isinstance(raw, dict) and "behaviors" in raw else raw
        for b in items:
            names.update(b.get("target_functions") or [])
    return names


def _injecagent_names() -> set[str]:
    names: set[str] = set()

    def walk(o) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("Tool", "User Tool") and isinstance(v, str):
                    names.add(v)
                elif k == "Attacker Tools" and isinstance(v, list):
                    names.update(x for x in v if isinstance(x, str))
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    for f in (DATA / "injecagent").glob("*.json"):
        walk(json.loads(f.read_text()))
    return names


def corpus() -> set[str]:
    names = _agentharm_names() | _injecagent_names()
    if not names:
        raise SystemExit(f"no tool names found under {DATA} — is the benchmark data present?")
    return names


def measure(names: set[str]) -> dict:
    b = EffectBoundary()
    unrecognized, effects = [], collections.Counter()
    for n in sorted(names):
        effect, recognized = b._classify(n)
        effects[effect.name] += 1
        if not recognized:
            unrecognized.append(n)
    return {
        "corpus_size": len(names),
        "sources": ["agentharm", "injecagent"],
        "unrecognized": len(unrecognized),
        "unrecognized_rate": round(len(unrecognized) / len(names), 4),
        "target_rate": TARGET,
        "meets_target": len(unrecognized) / len(names) <= TARGET,
        "effect_distribution": dict(effects.most_common()),
        "unrecognized_names": unrecognized,
    }


def main() -> int:
    r = measure(corpus())
    print(f"corpus            {r['corpus_size']} distinct real tool names {r['sources']}")
    print(
        f"UNRECOGNIZED      {r['unrecognized']} = {r['unrecognized_rate']:.1%}"
        f"   (target <={TARGET:.0%}: {'PASS' if r['meets_target'] else 'FAIL'})"
    )
    print(f"effects           {r['effect_distribution']}")
    if r["unrecognized_names"]:
        print("\nstill unrecognized:")
        for n in r["unrecognized_names"]:
            print(f"  {n}")
    out = Path(__file__).resolve().parent / "results" / "effect_coverage.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
