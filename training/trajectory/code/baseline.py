"""Baselines for the prefix risk scorer, run BEFORE the model exists.

Two of them, and the model has to beat both or it does not ship:

  counting   logistic regression over cheap prefix features -- effect-class counts, severity
             stats, step count. No arguments read, no sequence order beyond the trend term.
             If an 0.8B LoRA cannot beat counting tool types, the model is not learning
             trajectory structure, it is learning the corpus.

  audit      the four existing hand-written detectors in core/audit.py, replayed at every
             prefix. This is what Jataayu ships today, so it is the number the model must
             improve on to justify its existence in the stack.

Everything is scored AT PREFIX: for k in 1..n, score steps 1..k. That is the deployable
question and it is what nothing published measures -- every existing artifact scores a
finished trajectory.

Run:  python training/trajectory/code/baseline.py --data training/trajectory/data/splits
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from jataayu.core.audit import SessionTrace  # noqa: E402
from jataayu.guards.effect_boundary import EffectBoundary, EffectClass, Provenance  # noqa: E402

_BOUNDARY = EffectBoundary()
_CLASSES = list(EffectClass)


def prefix_features(steps: list[dict]) -> np.ndarray:
    """Counts, severity stats and a trend term over the prefix. Deliberately shallow."""
    effs = [_BOUNDARY.classify(s["tool"]) for s in steps]
    sev = [e.severity for e in effs]
    counts = [sum(1 for e in effs if e is c) for c in _CLASSES]
    n = len(steps)
    trend = (sev[-1] - sev[0]) / n if n > 1 else 0.0
    return np.array(
        [*counts, n, max(sev), sum(sev) / n, sev[-1], trend, len(set(s["tool"] for s in steps))],
        dtype=np.float32,
    )


def expand(trajs: list[dict], *, stride: int = 1, max_prefixes: int = 12):
    """One row per prefix. Long trajectories are subsampled so a 75-step BashArena trace does
    not outweigh 40 short AgentDojo ones."""
    X, y, meta = [], [], []
    for t in trajs:
        steps = t["steps"]
        ks = list(range(1, len(steps) + 1, stride))
        if len(ks) > max_prefixes:
            ks = [ks[i] for i in np.linspace(0, len(ks) - 1, max_prefixes).astype(int)]
        for k in ks:
            X.append(prefix_features(steps[:k]))
            y.append(t["label"])
            meta.append({"tid": t["tid"], "k": k, "n": len(steps), "bucket": t["bucket"]})
    return np.array(X), np.array(y), meta


def audit_first_flag(t: dict, *, untrusted: bool) -> int | None:
    """First prefix at which the existing detectors raise. 1-indexed; None = never."""
    prov = Provenance.UNTRUSTED if untrusted else Provenance.TRUSTED
    trace = SessionTrace(session_id=t["tid"])
    for i, s in enumerate(t["steps"], start=1):
        trace.record(s["tool"], provenance=prov, turn=i)
        if not trace.audit().is_clean:
            return i
    return None


def auc(y: np.ndarray, scores: np.ndarray) -> float:
    """Rank-based AUC; no sklearn dependency for the metric itself."""
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=float)
    ranks[order] = np.arange(1, len(scores) + 1)
    pos, neg = y == 1, y == 0
    if not pos.any() or not neg.any():
        return float("nan")
    return float((ranks[pos].sum() - pos.sum() * (pos.sum() + 1) / 2) / (pos.sum() * neg.sum()))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    args = ap.parse_args()
    load = lambda n: [json.loads(x) for x in (args.data / f"{n}.jsonl").open()]  # noqa: E731

    train = load("train")
    tests = {n: load(n) for n in ("val", "test_agentdojo_banking", "test_basharena")}

    # -- counting baseline
    from sklearn.linear_model import LogisticRegression

    Xtr, ytr, _ = expand(train)
    clf = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xtr, ytr)
    print(f"counting baseline trained on {len(Xtr)} prefixes from {len(train)} trajectories\n")

    print(f"{'split':26} {'prefix AUC':>11} {'audit-untrusted':>16} {'audit-trusted':>14}")
    for name, rows in tests.items():
        X, y, _ = expand(rows)
        a = auc(y, clf.predict_proba(X)[:, 1])

        # the shipped detectors, both provenance settings
        line = [f"{name:26} {a:11.3f}"]
        for untrusted in (True, False):
            flags = [audit_first_flag(t, untrusted=untrusted) for t in rows]
            atk = [f for f, t in zip(flags, rows) if t["label"] == 1]
            ben = [f for f, t in zip(flags, rows) if t["label"] == 0]
            det = sum(1 for f in atk if f is not None) / max(1, len(atk))
            fp = sum(1 for f in ben if f is not None) / max(1, len(ben))
            line.append(f"{det:6.1%}/{fp:<6.1%}".rjust(16 if untrusted else 14))
        print("".join(line))
    print("\n(detection% / false-flag% for the audit columns)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
