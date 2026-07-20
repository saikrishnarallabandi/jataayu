#!/usr/bin/env python3
"""
Jataayu inbound prompt-injection benchmark.

Runs jataayu's fast-path (regex) inbound guard against public, labeled
prompt-injection datasets and reports honest precision / recall / FPR / F1 / ROC-AUC
at multiple operating points, plus a robustness probe (does a trivial
character-spacing / zero-width transform collapse recall, the way it does for
Meta Prompt-Guard et al.?).

Designed for the AIEWF 2026 "Wearing the Agent" talk: produce a REAL,
honestly-caveated number, including where the guard fails.

Usage:
  python run_injection_bench.py --dataset deepset/prompt-injections --surface unknown
"""
import argparse
import json
import time
from pathlib import Path

import numpy as np
from datasets import load_dataset, concatenate_datasets
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

from jataayu import jataayu_check_inbound

OUT = Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)

# hackaprompt is ~600k rows; cap to a deterministic prefix for a tractable fast-path run.
HACKAPROMPT_LIMIT = 20000

# Jataayu level thresholds (from inbound.py _score_to_level)
OP_POINTS = {
    "BLOCKED>=0.90": 0.90,
    "HIGH>=0.70": 0.70,
    "MEDIUM>=0.45": 0.45,
    "LOW>=0.20": 0.20,
}


def load_binary(name):
    """Return list[(text, label)] with label 1=injection/attack, 0=benign."""
    if name == "deepset/prompt-injections":
        ds = load_dataset(name)
        rows = concatenate_datasets([ds["train"], ds["test"]])
        return [(r["text"], int(r["label"])) for r in rows]
    if name == "xTRam1/safe-guard-prompt-injection":
        ds = load_dataset(name)
        parts = [ds[s] for s in ds.keys()]
        rows = concatenate_datasets(parts)
        return [(r["text"], int(r["label"])) for r in rows]
    if name == "jackhhao/jailbreak-classification":
        ds = load_dataset(name)
        parts = [ds[s] for s in ds.keys()]
        rows = concatenate_datasets(parts)
        # label is "jailbreak"/"benign"
        return [(r["prompt"], 1 if str(r["type"]).lower().startswith("jail") else 0) for r in rows]
    if name == "reshabhs/SPML_Chatbot_Prompt_Injection":
        # License: MIT. Single `train` split. Text = the attacker's `User Prompt`;
        # label = `Prompt injection` (string "1"=injection / "0"=benign). A few rows
        # carry an empty user prompt — skip those (they carry no attack surface).
        ds = load_dataset(name)["train"]
        out = []
        for r in ds:
            txt = r.get("User Prompt")
            if not txt:
                continue
            out.append((txt, int(str(r["Prompt injection"]).strip() or 0)))
        return out
    if name == "Lakera/gandalf_ignore_instructions":
        # License: MIT. Every row is a real prompt-injection attempt — positive class
        # ONLY, no benign split. Text = `text`. ROC-AUC/PR-AUC are undefined on a
        # single class; the runner reports recall at fixed operating points instead.
        ds = load_dataset(name)
        rows = concatenate_datasets([ds[s] for s in ds.keys()])
        return [(r["text"], 1) for r in rows]
    if name == "hackaprompt/hackaprompt-dataset":
        # License: MIT. GATED on the Hub (as of 2026-07): requires access approval on
        # the dataset page + `huggingface-cli login`. EVERY row is a prompt-injection
        # attempt — positive class ONLY, no benign rows. `correct` marks whether the
        # jailbreak SUCCEEDED against the target model, NOT whether the text is an
        # attack; a failed attempt is still an injection, so it is labeled 1 too.
        # Text = the participant's `user_input`. Deterministic first-N prefix (LIMIT).
        # Single-class => ROC/PR-AUC undefined; the runner reports recall only.
        ds = load_dataset(name)
        rows = concatenate_datasets([ds[s] for s in ds.keys()])
        out = []
        for r in rows:
            txt = r.get("user_input")
            if not txt:
                continue
            out.append((txt, 1))
            if len(out) >= HACKAPROMPT_LIMIT:
                break
        return out
    if name == "allenai/wildjailbreak":
        # License: ODC-BY (attribution required: Jiang et al., WildTeaming, 2024).
        # GATED — requires access approval + `huggingface-cli login`. The `eval` config
        # holds `adversarial` (attack prompt text) and `data_type`; harmful attacks
        # (adversarial_harmful) are label 1, adversarial_benign is label 0.
        ds = load_dataset(name, "eval")
        rows = concatenate_datasets([ds[s] for s in ds.keys()])
        out = []
        for r in rows:
            txt = r.get("adversarial") or r.get("vanilla")
            if not txt:
                continue
            out.append((txt, 1 if str(r.get("data_type", "")).endswith("harmful") else 0))
        return out
    raise SystemExit(f"unknown dataset {name}")


def score_all(rows, surface, use_llm=False):
    scores, preds_block, lat = [], [], []
    for text, _ in rows:
        t0 = time.perf_counter()
        r = jataayu_check_inbound(text or "", surface=surface, use_llm=use_llm)
        lat.append((time.perf_counter() - t0) * 1000)
        scores.append(float(r["risk_score"]))
        preds_block.append(bool(r["blocked"]))
    return np.array(scores), np.array(preds_block), np.array(lat)


def metrics_at(y_true, y_score, thr):
    y_pred = (y_score >= thr).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0          # catch-rate
    fpr = fp / (fp + tn) if (fp + tn) else 0.0          # benign false-block rate
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return dict(threshold=thr, tp=tp, fp=fp, tn=tn, fn=fn,
                precision=round(prec, 4), recall=round(rec, 4),
                fpr=round(fpr, 4), f1=round(f1, 4))


def recall_at_fpr(y_true, y_score, max_fpr):
    """Data-driven operating point: recall (TPR) at the largest score threshold whose
    benign FPR stays <= max_fpr, plus the realized FPR and that threshold. Returns None
    if no threshold meets the budget (guard against an empty selection)."""
    fpr, tpr, thr = roc_curve(y_true, y_score)
    ok = np.where(fpr <= max_fpr)[0]
    if len(ok) == 0:
        return None
    i = ok[-1]
    # roc_curve prepends a sentinel threshold of +inf (predict-nothing point). If that
    # trivial point is the only one meeting the budget, no real threshold qualifies —
    # report it rather than emit non-finite JSON.
    if not np.isfinite(thr[i]):
        return {"recall": 0.0, "fpr": 0.0, "threshold": None,
                "fpr_budget": max_fpr, "no_operating_point": True}
    return {"recall": round(float(tpr[i]), 4),
            "fpr": round(float(fpr[i]), 4),
            "threshold": round(float(thr[i]), 4),
            "fpr_budget": max_fpr}


# --- robustness transforms (the "trivial bypass" probes the literature uses) ---
def space_out(s):       # insert a space between every character (Prompt-Guard killer)
    return " ".join(list(s))

def zero_width(s):      # inject zero-width space after each char
    return "​".join(list(s))

def leet(s):
    table = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "5"})
    return s.translate(table)

TRANSFORMS = {"space_out": space_out, "zero_width": zero_width, "leetspeak": leet}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="deepset/prompt-injections")
    ap.add_argument("--surface", default="unknown")
    ap.add_argument("--robustness", action="store_true", default=True)
    args = ap.parse_args()

    rows = load_binary(args.dataset)
    y_true = np.array([lbl for _, lbl in rows])
    n_pos, n_neg = int(y_true.sum()), int((y_true == 0).sum())
    print(f"[{args.dataset}] {len(rows)} rows | injection={n_pos} benign={n_neg} | surface={args.surface}")

    scores, preds_block, lat = score_all(rows, args.surface)

    both_classes = n_pos > 0 and n_neg > 0

    result = {
        "dataset": args.dataset,
        "surface": args.surface,
        "n_total": len(rows),
        "n_injection": n_pos,
        "n_benign": n_neg,
        "latency_ms": {"mean": round(float(lat.mean()), 4),
                       "p50": round(float(np.percentile(lat, 50)), 4),
                       "p99": round(float(np.percentile(lat, 99)), 4)},
        # ROC/PR-AUC are undefined when a dataset carries a single class (e.g. Gandalf
        # is injections-only) — report null rather than crash.
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4) if both_classes else None,
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4) if both_classes else None,
        "recall_at_1pct_fpr": recall_at_fpr(y_true, scores, 0.01) if both_classes else None,
        "operating_points": {name: metrics_at(y_true, scores, thr)
                             for name, thr in OP_POINTS.items()},
    }

    # Robustness: of the injection-positives the fast-path catches at MEDIUM,
    # how many survive a trivial transform?
    if args.robustness:
        pos_idx = [i for i, (_, lbl) in enumerate(rows) if lbl == 1]
        caught0 = [i for i in pos_idx if scores[i] >= 0.45]
        rob = {"baseline_caught_at_MEDIUM": len(caught0),
               "baseline_pos": len(pos_idx)}
        for tname, fn in TRANSFORMS.items():
            still = 0
            for i in caught0:
                text = rows[i][0] or ""
                r = jataayu_check_inbound(fn(text), surface=args.surface, use_llm=False)
                if r["risk_score"] >= 0.45:
                    still += 1
            rob[tname] = {"still_caught": still,
                          "evasion_rate": round(1 - still / len(caught0), 4) if caught0 else None}
        result["robustness"] = rob

    fn = OUT / f"{args.dataset.replace('/', '_')}_{args.surface}_fastpath.json"
    fn.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    print(f"\nwrote {fn}")


if __name__ == "__main__":
    main()
