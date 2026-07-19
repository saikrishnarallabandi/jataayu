#!/usr/bin/env python3
"""
Leave-One-Dataset-Out (LODO) honesty artifact for jataayu's inbound fast path.

The fast-path decision is a threshold on the raw risk score. A benchmark that
selects that threshold *on the same distribution it reports on* flatters itself:
the operating point is fit to the test set. This runner instead measures the
transfer gap — "When Benchmarks Lie":

  For each held-out dataset D:
    1. POOL every other wired dataset, fit the operating threshold t* on the pool
       at a 1%-FPR budget (the deployment rule: keep benign false-blocks <= 1%).
    2. Apply t* to D (OUT-OF-DISTRIBUTION): report recall + realized FPR on D.
    3. Compare against the IN-DISTRIBUTION reference: the threshold fit on D's own
       1%-FPR point. The OOD gap = in-dist recall - OOD recall (how much catch-rate
       you actually lose when the threshold was tuned elsewhere), plus the FPR drift
       (how far the realized benign false-block rate drifts from the 1% budget).

Also reports each held-out dataset's threshold-independent ROC-AUC.

Fast path only (regex/CPU, no LLM, no GPU). Scores every dataset once and reuses
the cache for every pooled fit. Datasets that fail to load (e.g. gated sets without
`huggingface-cli login`) are skipped with a recorded reason and never silently
counted. Single-class sets (Gandalf: injections only) contribute their positives to
every pool but can only report the metrics that are defined without a benign class.

Usage:
  python benchmarks/run_lodo_fastpath.py
  python benchmarks/run_lodo_fastpath.py --datasets deepset/prompt-injections xTRam1/safe-guard-prompt-injection
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from run_injection_bench import load_binary, score_all  # noqa: E402

OUT = HERE / "results"
OUT.mkdir(exist_ok=True)

DEFAULT_DATASETS = [
    "deepset/prompt-injections",
    "xTRam1/safe-guard-prompt-injection",
    "jackhhao/jailbreak-classification",
    "reshabhs/SPML_Chatbot_Prompt_Injection",
    "Lakera/gandalf_ignore_instructions",
    # Gated — included so they join the pool once access is granted; skipped otherwise.
    "hackaprompt/hackaprompt-dataset",
    "allenai/wildjailbreak",
]


def threshold_at_fpr(y, s, max_fpr):
    """Highest score threshold whose benign FPR on (y, s) stays <= max_fpr.

    Returns (threshold, realized_fpr, recall_at_that_threshold) or None if the set
    has no benign rows (FPR undefined) or no threshold meets the budget."""
    from sklearn.metrics import roc_curve
    if (y == 0).sum() == 0 or (y == 1).sum() == 0:
        return None
    fpr, tpr, thr = roc_curve(y, s)
    ok = np.where(fpr <= max_fpr)[0]
    if len(ok) == 0:
        return None
    i = ok[-1]
    # roc_curve prepends a +inf sentinel threshold (predict-nothing). If only that
    # trivial point meets the budget, there is no usable real threshold.
    if not np.isfinite(thr[i]):
        return None
    return float(thr[i]), float(fpr[i]), float(tpr[i])


def apply_threshold(y, s, t):
    """Recall and realized FPR of threshold t on (y, s). recall/fpr are None when the
    corresponding class is absent."""
    pos = y == 1
    neg = y == 0
    recall = float((s[pos] >= t).mean()) if pos.any() else None
    fpr = float((s[neg] >= t).mean()) if neg.any() else None
    return recall, fpr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", nargs="+", default=DEFAULT_DATASETS)
    ap.add_argument("--surface", default="unknown")
    ap.add_argument("--fpr-budget", type=float, default=0.01)
    ap.add_argument("--out", default=str(OUT / "lodo_fastpath.json"))
    args = ap.parse_args()

    # ---- score every dataset once (cache scores + labels) --------------------
    cache = {}          # name -> (y_true, scores)
    skipped = {}        # name -> reason
    for name in args.datasets:
        try:
            rows = load_binary(name)
        except Exception as e:
            skipped[name] = f"{type(e).__name__}: {str(e)[:200]}"
            print(f"[skip] {name}: {skipped[name]}")
            continue
        if not rows:
            skipped[name] = "loaded 0 rows"
            print(f"[skip] {name}: {skipped[name]}")
            continue
        y = np.array([lbl for _, lbl in rows])
        scores, _, _ = score_all(rows, args.surface)
        cache[name] = (y, scores)
        print(f"[ok]   {name}: n={len(rows)} pos={int((y==1).sum())} neg={int((y==0).sum())}")

    from sklearn.metrics import roc_auc_score

    # Only MIXED-label datasets can supply pool negatives to fit the FPR threshold.
    # All-positive sets (Gandalf, hackaprompt) have no true negatives, so they can be
    # held-out recall-only rows but must NEVER contribute to the pool.
    mixed = [n for n in cache if (cache[n][0] == 0).any() and (cache[n][0] == 1).any()]

    per_held_out = {}
    for held in cache:
        y_h, s_h = cache[held]
        # Pool = every mixed-label dataset except the held-out one.
        others = [n for n in mixed if n != held]
        if not others:
            per_held_out[held] = {"note": "no mixed-label datasets available to pool"}
            continue

        # POOL the other mixed datasets and fit t* at the FPR budget.
        y_pool = np.concatenate([cache[n][0] for n in others])
        s_pool = np.concatenate([cache[n][1] for n in others])
        pooled_fit = threshold_at_fpr(y_pool, s_pool, args.fpr_budget)

        entry = {
            "n": int(len(y_h)),
            "n_pos": int((y_h == 1).sum()),
            "n_neg": int((y_h == 0).sum()),
            "single_class": held not in mixed,
            "pooled_from": others,
            "roc_auc": (round(float(roc_auc_score(y_h, s_h)), 4)
                        if (y_h == 0).any() and (y_h == 1).any() else None),
        }

        # IN-DISTRIBUTION reference: threshold fit on the held-out set itself.
        indist_fit = threshold_at_fpr(y_h, s_h, args.fpr_budget)
        entry["in_distribution"] = (
            {"threshold": round(indist_fit[0], 4),
             "recall_at_1pct_fpr": round(indist_fit[2], 4),
             "realized_fpr": round(indist_fit[1], 4)}
            if indist_fit else None)

        # OUT-OF-DISTRIBUTION: pooled threshold transferred onto the held-out set.
        if pooled_fit is None:
            entry["ood"] = None
            entry["ood_note"] = "pooled set has no usable 1%-FPR threshold"
        else:
            t_star = pooled_fit[0]
            ood_recall, ood_fpr = apply_threshold(y_h, s_h, t_star)
            entry["ood"] = {
                "pooled_threshold": round(t_star, 4),
                "pooled_fit_fpr": round(pooled_fit[1], 4),
                "recall": round(ood_recall, 4) if ood_recall is not None else None,
                "realized_fpr": round(ood_fpr, 4) if ood_fpr is not None else None,
            }
            # OOD gap: catch-rate lost by transferring the threshold, and FPR drift.
            if indist_fit and ood_recall is not None:
                entry["ood_gap"] = {
                    "recall_drop": round(indist_fit[2] - ood_recall, 4),
                    "fpr_drift": (round(ood_fpr - args.fpr_budget, 4)
                                  if ood_fpr is not None else None),
                }
        per_held_out[held] = entry

    result = {
        "benchmark": "Jataayu inbound fast-path — Leave-One-Dataset-Out (LODO)",
        "api": "jataayu_check_inbound (fast path, no LLM)",
        "surface": args.surface,
        "fpr_budget": args.fpr_budget,
        "protocol": ("threshold fit on POOLED other datasets at the FPR budget, then "
                     "evaluated on the held-out set; in-distribution reference fits the "
                     "threshold on the held-out set itself."),
        "datasets_evaluated": list(cache.keys()),
        "mixed_label_pool": mixed,
        "single_class_eval_only": [n for n in cache if n not in mixed],
        "datasets_skipped": skipped,
        "per_held_out": per_held_out,
    }
    Path(args.out).write_text(json.dumps(result, indent=2))

    # ---- console table -------------------------------------------------------
    print(f"\n{'held-out':46} {'ROC-AUC':>8} {'R@1%(in)':>9} {'R(OOD)':>8} "
          f"{'FPR(OOD)':>9} {'gap':>7}")
    for name, e in per_held_out.items():
        if "note" in e:
            print(f"{name:46} {e['note']}")
            continue
        auc = "-" if e["roc_auc"] is None else f"{e['roc_auc']:.4f}"
        rin = "-" if not e["in_distribution"] else f"{e['in_distribution']['recall_at_1pct_fpr']:.4f}"
        rood = "-" if not e["ood"] or e["ood"]["recall"] is None else f"{e['ood']['recall']:.4f}"
        food = "-" if not e["ood"] or e["ood"]["realized_fpr"] is None else f"{e['ood']['realized_fpr']:.4f}"
        gap = "-" if "ood_gap" not in e else f"{e['ood_gap']['recall_drop']:+.4f}"
        print(f"{name:46} {auc:>8} {rin:>9} {rood:>8} {food:>9} {gap:>7}")
    if skipped:
        print("\nskipped:")
        for n, r in skipped.items():
            print(f"  {n}: {r}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
