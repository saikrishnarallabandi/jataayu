#!/usr/bin/env python3
"""
Head-to-head evaluation of competing prompt-injection DETECTORS against Jataayu,
on the EXACT same rows / labels / splits and the EXACT same evasion transforms
used by benchmarks/run_injection_bench.py.

For each (detector x dataset) we report, apples-to-apples with Jataayu:
  - ROC-AUC, PR-AUC over the injection score
  - precision / recall / FPR / F1 at the model's natural 0.5 threshold
  - recall @ 1% FPR (how these detectors are usually judged)
  - evasion_rate under space_out / zero_width / leetspeak: of the positives the
    detector CATCHES on clean text (at its threshold), what fraction FLIP TO MISSED
    after a trivial character perturbation. This is the crucial column: Jataayu's
    regex-anchored guard holds ~0 evasion; ML classifiers tend to collapse.

Competitors (HuggingFace, run locally on GPU, batched, id2label-verified):
  - protectai/deberta-v3-base-prompt-injection-v2   (open, 2-class)
  - protectai/deberta-v3-base-prompt-injection       (open, 2-class, v1)
  - deepset/deberta-v3-base-injection                (open, 2-class)
  - meta-llama/Prompt-Guard-86M                       (gated; 3-class BENIGN/INJECTION/JAILBREAK)

Jataayu's fast-path (regex, use_llm=False) is re-emitted on the identical loaded
rows as a sanity/anchor row (should reproduce deepset ROC-AUC ~= 0.63).

Usage:
  python run_detector_headtohead.py --limit 50          # smoke test
  python run_detector_headtohead.py                      # FULL run
  python run_detector_headtohead.py --models protectai/deberta-v3-base-prompt-injection-v2
"""
import argparse, json, time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

# Reuse the EXACT data loader + evasion transforms from our own runner so rows,
# labels, splits, and perturbations are byte-for-byte identical.
from run_injection_bench import load_binary, TRANSFORMS, metrics_at
from jataayu import jataayu_check_inbound

OUT = Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)

DATASETS = [
    "deepset/prompt-injections",
    "xTRam1/safe-guard-prompt-injection",
    "jackhhao/jailbreak-classification",
]

COMPETITORS = [
    "protectai/deberta-v3-base-prompt-injection-v2",
    "protectai/deberta-v3-base-prompt-injection",
    "deepset/deberta-v3-base-injection",
    "meta-llama/Prompt-Guard-86M",
]

# Label names that denote the injection/attack class (verified per-model from id2label).
INJ_TOKENS = ("INJECT", "JAILBREAK", "UNSAFE", "ATTACK", "MALICIOUS")
BENIGN_TOKENS = ("SAFE", "BENIGN", "LEGIT", "CLEAN", "NEGATIVE", "0")

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def resolve_injection_map(id2label):
    """Return (mapping_desc, fn(probs)->inj_score) from a model's id2label.

    2-class: inj_score = P(injection-labelled class).
    3-class (Prompt-Guard BENIGN/INJECTION/JAILBREAK): inj_score = 1 - P(BENIGN)
       == P(INJECTION)+P(JAILBREAK). Documented explicitly, not guessed.
    """
    labels = {int(k): str(v) for k, v in id2label.items()}
    up = {i: n.upper() for i, n in labels.items()}
    inj_idx = [i for i, n in up.items() if any(t in n for t in INJ_TOKENS)]
    ben_idx = [i for i, n in up.items() if any(t in n for t in BENIGN_TOKENS)]

    if len(labels) == 2:
        if len(inj_idx) == 1:
            idx = inj_idx[0]
            return (f"P(label {idx}='{labels[idx]}')  [id2label={labels}]",
                    lambda p, idx=idx: p[:, idx])
        # fall back: injection = non-benign class
        if len(ben_idx) == 1:
            idx = 1 - ben_idx[0]
            return (f"P(label {idx}='{labels[idx]}', non-benign)  [id2label={labels}]",
                    lambda p, idx=idx: p[:, idx])
        # last resort: assume idx 1 is positive
        return (f"P(label 1='{labels.get(1)}') [AMBIGUOUS, assumed] [id2label={labels}]",
                lambda p: p[:, 1])

    # >=3 classes -> Prompt-Guard style. inj = 1 - P(benign).
    if len(ben_idx) >= 1:
        b = ben_idx[0]
        combined = "+".join(f"'{labels[i]}'" for i in inj_idx) if inj_idx else "non-benign"
        return (f"1 - P('{labels[b]}')  == P({combined})  [3-class id2label={labels}]",
                lambda p, b=b: 1.0 - p[:, b])
    # no benign found: sum injection-labelled classes
    idxs = inj_idx or list(labels.keys())[1:]
    return (f"sum P({idxs})  [AMBIGUOUS 3-class] [id2label={labels}]",
            lambda p, idxs=idxs: p[:, idxs].sum(axis=1))


def load_detector(model_id):
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.to(DEVICE).eval()
    id2label = model.config.id2label
    desc, fn = resolve_injection_map(id2label)
    maxlen = min(getattr(tok, "model_max_length", 512) or 512, 512)
    return tok, model, fn, desc, maxlen


def _is_oom(e):
    """CUDA OOM can surface as torch.cuda.OutOfMemoryError OR a plain RuntimeError
    (e.g. from the deberta disentangled-attention TorchScript JIT). Catch both."""
    return isinstance(e, torch.cuda.OutOfMemoryError) or (
        isinstance(e, RuntimeError) and "out of memory" in str(e).lower())


@torch.no_grad()
def _forward(chunk, tok, model, inj_fn, maxlen, device):
    enc = tok(chunk, return_tensors="pt", truncation=True,
              max_length=maxlen, padding=True).to(device)
    logits = model(**enc).logits
    probs = torch.softmax(logits, dim=-1).cpu().numpy()
    return inj_fn(probs)


def score_texts(texts, tok, model, inj_fn, maxlen, batch_size=16):
    """Injection scores in [0,1], deterministic (eval, no sampling).

    Robust to a contended GPU: on CUDA OOM, empty cache and recursively halve the
    batch; a single row that still OOMs is scored on CPU so the run never stalls.
    """
    out = np.empty(len(texts), dtype=np.float64)

    def run(lo, hi, bs):
        i = lo
        while i < hi:
            chunk = [texts[j] if texts[j] else "" for j in range(i, min(i + bs, hi))]
            try:
                out[i:i + len(chunk)] = _forward(chunk, tok, model, inj_fn, maxlen, DEVICE)
                i += len(chunk)
            except Exception as e:
                if not _is_oom(e):
                    raise
                if DEVICE == "cuda":
                    torch.cuda.empty_cache()
                if bs > 1:
                    run(i, min(i + bs, hi), max(1, bs // 2))
                    i += len(chunk)
                else:
                    # single row too big even alone -> CPU fallback for this one row
                    model.to("cpu")
                    out[i] = _forward([chunk[0]], tok, model, inj_fn, maxlen, "cpu")[0]
                    model.to(DEVICE)
                    if DEVICE == "cuda":
                        torch.cuda.empty_cache()
                    i += 1

    run(0, len(texts), batch_size)
    return out


def recall_at_fpr(y_true, y_score, target_fpr=0.01):
    fpr, tpr, thr = roc_curve(y_true, y_score)
    ok = fpr <= target_fpr
    if not ok.any():
        return 0.0, None
    j = np.max(np.where(ok))
    return round(float(tpr[j]), 4), round(float(thr[j]), 6)


def eval_detector_on_dataset(rows, tok, model, inj_fn, maxlen, threshold=0.5,
                             batch_size=32, evasion_sample=None):
    texts = [t for t, _ in rows]
    y_true = np.array([lbl for _, lbl in rows])
    scores = score_texts(texts, tok, model, inj_fn, maxlen, batch_size)

    res = {
        "n": len(rows),
        "n_injection": int(y_true.sum()),
        "n_benign": int((y_true == 0).sum()),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4),
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4),
    }
    m = metrics_at(y_true, scores, threshold)
    res.update({k: m[k] for k in ("precision", "recall", "fpr", "f1", "tp", "fp", "tn", "fn")})
    res["threshold"] = threshold
    r1, t1 = recall_at_fpr(y_true, scores, 0.01)
    res["recall_at_1pct_fpr"] = r1
    res["threshold_at_1pct_fpr"] = t1

    # Evasion: positives CAUGHT on clean text at threshold -> perturb -> flip to MISSED?
    pos_idx = [i for i, (_, lbl) in enumerate(rows) if lbl == 1]
    caught_all = [i for i in pos_idx if scores[i] >= threshold]
    # Deterministic sample (first-N) of caught positives for the evasion RATE estimate,
    # so the probe is tractable on a contended GPU. Full clean metrics use all rows.
    caught0 = caught_all[:evasion_sample] if evasion_sample else caught_all
    evasion = {"baseline_caught_at_thr": len(caught_all),
               "evasion_probe_n": len(caught0), "baseline_pos": len(pos_idx)}
    for tname, tfn in TRANSFORMS.items():
        if not caught0:
            evasion[tname] = {"still_caught": 0, "evasion_rate": None}
            continue
        pert = [rows[i][0] or "" for i in caught0]
        pert = [tfn(t) for t in pert]
        pscores = score_texts(pert, tok, model, inj_fn, maxlen, batch_size)
        still = int((pscores >= threshold).sum())
        evasion[tname] = {"still_caught": still,
                          "evasion_rate": round(1 - still / len(caught0), 4)}
    res["evasion"] = evasion
    return res


def eval_jataayu_on_dataset(rows, threshold=0.45, evasion_sample=None):
    """Jataayu fast-path (regex, use_llm=False) on the identical rows. Anchor/sanity."""
    texts = [t for t, _ in rows]
    y_true = np.array([lbl for _, lbl in rows])
    scores = np.array([float(jataayu_check_inbound(t or "", surface="unknown",
                                                   use_llm=False)["risk_score"]) for t in texts])
    res = {
        "n": len(rows),
        "n_injection": int(y_true.sum()),
        "n_benign": int((y_true == 0).sum()),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4),
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4),
    }
    m = metrics_at(y_true, scores, threshold)  # MEDIUM>=0.45, same as run_injection_bench robustness
    res.update({k: m[k] for k in ("precision", "recall", "fpr", "f1", "tp", "fp", "tn", "fn")})
    res["threshold"] = threshold
    r1, t1 = recall_at_fpr(y_true, scores, 0.01)
    res["recall_at_1pct_fpr"] = r1
    res["threshold_at_1pct_fpr"] = t1

    pos_idx = [i for i, (_, lbl) in enumerate(rows) if lbl == 1]
    caught_all = [i for i in pos_idx if scores[i] >= threshold]
    caught0 = caught_all[:evasion_sample] if evasion_sample else caught_all
    evasion = {"baseline_caught_at_thr": len(caught_all),
               "evasion_probe_n": len(caught0), "baseline_pos": len(pos_idx)}
    for tname, tfn in TRANSFORMS.items():
        still = 0
        for i in caught0:
            s = jataayu_check_inbound(tfn(rows[i][0] or ""), surface="unknown",
                                      use_llm=False)["risk_score"]
            if s >= threshold:
                still += 1
        evasion[tname] = {"still_caught": still,
                          "evasion_rate": round(1 - still / len(caught0), 4) if caught0 else None}
    res["evasion"] = evasion
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", nargs="+", default=DATASETS)
    ap.add_argument("--models", nargs="+", default=COMPETITORS)
    ap.add_argument("--limit", type=int, default=None, help="rows per dataset (smoke test)")
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--evasion-sample", type=int, default=1000,
                    help="cap on caught-positives used for the evasion-rate probe (0=all)")
    ap.add_argument("--out", default=str(OUT / "detector_headtohead.json"))
    ap.add_argument("--no-resume", action="store_true",
                    help="ignore any existing --out file and recompute everything")
    args = ap.parse_args()

    t_start = time.time()
    # Load all datasets once (identical rows for every detector).
    loaded = {}
    for d in args.datasets:
        rows = load_binary(d)
        if args.limit:
            # keep a balanced-ish slice deterministically: first N/2 pos, first N/2 neg
            pos = [r for r in rows if r[1] == 1][:args.limit // 2]
            neg = [r for r in rows if r[1] == 0][:args.limit - len(pos)]
            rows = pos + neg
        loaded[d] = rows
        print(f"[data] {d}: {len(rows)} rows "
              f"(inj={sum(1 for _,l in rows if l==1)}, benign={sum(1 for _,l in rows if l==0)})")

    # Resume: reuse any prior complete entries so a crash under GPU contention
    # never discards finished detectors. Rerunning continues where it left off.
    results = {"_meta": {"device": DEVICE, "limit": args.limit,
                         "batch_size": args.batch_size,
                         "transforms": list(TRANSFORMS.keys()),
                         "evasion_sample_cap": args.evasion_sample,
                         "datasets": args.datasets}}
    availability = {}
    if not args.no_resume and Path(args.out).exists():
        try:
            prior = json.loads(Path(args.out).read_text())
            for k, v in prior.items():
                if k == "_meta":
                    continue
                results[k] = v
            availability = prior.get("_meta", {}).get("availability", {})
            print(f"[resume] loaded prior results for: {[k for k in results if k!='_meta']}")
        except Exception as e:
            print(f"[resume] could not load prior ({e}); starting fresh")

    def complete(entry, need_error_ok=True):
        """A stored entry is complete if it has every dataset (or is a load error)."""
        if not isinstance(entry, dict):
            return False
        if entry.get("_error"):
            return True
        return all(d in entry for d in args.datasets)

    def save():
        results["_meta"]["availability"] = availability
        results["_meta"]["wall_time_sec"] = round(time.time() - t_start, 1)
        Path(args.out).write_text(json.dumps(results, indent=2, ensure_ascii=False))

    esample = args.evasion_sample or None

    # Jataayu anchor row first.
    print("\n=== Jataayu (fast-path, regex, use_llm=False) ===")
    if complete(results.get("jataayu_fastpath")):
        print("  [skip] already computed")
    else:
        jat = {"_injection_label_mapping": "risk_score >= 0.45 (MEDIUM); regex fast-path"}
        for d, rows in loaded.items():
            r = eval_jataayu_on_dataset(rows, evasion_sample=esample)
            jat[d] = r
            print(f"  {d}: AUC={r['roc_auc']} recall={r['recall']} fpr={r['fpr']} "
                  f"evasion(space/zw/leet)="
                  f"{r['evasion']['space_out']['evasion_rate']}/"
                  f"{r['evasion']['zero_width']['evasion_rate']}/"
                  f"{r['evasion']['leetspeak']['evasion_rate']}")
        results["jataayu_fastpath"] = jat
        availability["jataayu_fastpath"] = "OK"
        save()

    for model_id in args.models:
        print(f"\n=== {model_id} ===")
        if complete(results.get(model_id)) and not (isinstance(results.get(model_id), dict)
                                                    and results[model_id].get("_error")):
            print("  [skip] already computed")
            continue
        try:
            tok, model, inj_fn, desc, maxlen = load_detector(model_id)
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            short = msg.splitlines()[0][:300]
            gated = any(c in msg for c in ("401", "403", "gated", "restricted",
                                           "awaiting", "access to model", "authorized"))
            status = "NOT AVAILABLE (gated/license not accepted)" if gated else f"LOAD FAILED"
            print(f"  {status}: {short}")
            availability[model_id] = f"{status}: {short}"
            results[model_id] = {"_error": short, "_status": status}
            continue

        print(f"  loaded on {DEVICE}; injection score = {desc}; max_len={maxlen}")
        # reuse any datasets already done for this model (partial-crash resume)
        det = results.get(model_id, {})
        if not isinstance(det, dict) or det.get("_error"):
            det = {}
        det["_injection_label_mapping"] = desc
        det["_max_length"] = maxlen
        results[model_id] = det
        for d, rows in loaded.items():
            if d in det and isinstance(det[d], dict) and "roc_auc" in det[d]:
                print(f"  {d}: [skip] already computed")
                continue
            r = eval_detector_on_dataset(rows, tok, model, inj_fn, maxlen,
                                         batch_size=args.batch_size,
                                         evasion_sample=esample)
            det[d] = r
            print(f"  {d}: AUC={r['roc_auc']} recall={r['recall']} fpr={r['fpr']} "
                  f"r@1%fpr={r['recall_at_1pct_fpr']} "
                  f"evasion(space/zw/leet)="
                  f"{r['evasion']['space_out']['evasion_rate']}/"
                  f"{r['evasion']['zero_width']['evasion_rate']}/"
                  f"{r['evasion']['leetspeak']['evasion_rate']}")
            availability[model_id] = "OK"
            save()   # incremental: survive a crash on a later dataset/model
        del model, tok
        if DEVICE == "cuda":
            torch.cuda.empty_cache()

    save()
    print(f"\nwall_time={results['_meta']['wall_time_sec']}s")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
