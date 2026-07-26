#!/usr/bin/env python3
"""
Score the fixed eval cache with an off-the-shelf ENCODER prompt-injection detector
(HF sequence classifier), writing qwen_scores/<tag>.jsonl in the SAME [0,100] score
format as the Qwen judges so the leaderboard aggregator treats them identically.

Self-contained (no jataayu import): the id2label injection mapping + OOM-robust
batched scorer are copied from run_detector_headtohead.py. Score = 100 * P(injection).

Run in a torch env (conda suchilm):
  python score_encoder.py --model protectai/deberta-v3-base-prompt-injection-v2 \
      --tag enc-protectai-v2
"""

import argparse
import json
from pathlib import Path
import numpy as np
import torch

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
CACHE = EVAL / "results" / "qwen_scores" / "eval_cache.jsonl"
OUTDIR = EVAL / "results" / "qwen_scores"

INJ_TOKENS = ("INJECT", "JAILBREAK", "UNSAFE", "ATTACK", "MALICIOUS")
BENIGN_TOKENS = ("SAFE", "BENIGN", "LEGIT", "CLEAN", "NEGATIVE", "0")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def resolve_injection_map(id2label):
    labels = {int(k): str(v) for k, v in id2label.items()}
    up = {i: n.upper() for i, n in labels.items()}
    inj_idx = [i for i, n in up.items() if any(t in n for t in INJ_TOKENS)]
    ben_idx = [i for i, n in up.items() if any(t in n for t in BENIGN_TOKENS)]
    if len(labels) == 2:
        if len(inj_idx) == 1:
            idx = inj_idx[0]
            return (
                f"P(label {idx}='{labels[idx]}') [id2label={labels}]",
                lambda p, idx=idx: p[:, idx],
            )
        if len(ben_idx) == 1:
            idx = 1 - ben_idx[0]
            return (
                f"P(label {idx}='{labels[idx]}', non-benign) [id2label={labels}]",
                lambda p, idx=idx: p[:, idx],
            )
        return (f"P(label 1='{labels.get(1)}') [AMBIGUOUS] [id2label={labels}]", lambda p: p[:, 1])
    if len(ben_idx) >= 1:
        b = ben_idx[0]
        combined = "+".join(f"'{labels[i]}'" for i in inj_idx) if inj_idx else "non-benign"
        return (
            f"1 - P('{labels[b]}') == P({combined}) [3-class id2label={labels}]",
            lambda p, b=b: 1.0 - p[:, b],
        )
    idxs = inj_idx or list(labels.keys())[1:]
    return (
        f"sum P({idxs}) [AMBIGUOUS 3-class] [id2label={labels}]",
        lambda p, idxs=idxs: p[:, idxs].sum(axis=1),
    )


def load_detector(model_id):
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id).to(DEVICE).eval()
    desc, fn = resolve_injection_map(model.config.id2label)
    maxlen = min(getattr(tok, "model_max_length", 512) or 512, 512)
    return tok, model, fn, desc, maxlen


def _is_oom(e):
    return isinstance(e, torch.cuda.OutOfMemoryError) or (
        isinstance(e, RuntimeError) and "out of memory" in str(e).lower()
    )


@torch.no_grad()
def _forward(chunk, tok, model, inj_fn, maxlen, device):
    enc = tok(chunk, return_tensors="pt", truncation=True, max_length=maxlen, padding=True).to(
        device
    )
    probs = torch.softmax(model(**enc).logits, dim=-1).cpu().numpy()
    return inj_fn(probs)


def score_texts(texts, tok, model, inj_fn, maxlen, batch_size=16):
    out = np.empty(len(texts), dtype=np.float64)

    def run(lo, hi, bs):
        i = lo
        while i < hi:
            chunk = [texts[j] if texts[j] else "" for j in range(i, min(i + bs, hi))]
            try:
                out[i : i + len(chunk)] = _forward(chunk, tok, model, inj_fn, maxlen, DEVICE)
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
                    model.to("cpu")
                    out[i] = _forward([chunk[0]], tok, model, inj_fn, maxlen, "cpu")[0]
                    model.to(DEVICE)
                    if DEVICE == "cuda":
                        torch.cuda.empty_cache()
                    i += 1

    run(0, len(texts), batch_size)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--batch-size", type=int, default=16)
    args = ap.parse_args()

    try:
        tok, model, inj_fn, desc, maxlen = load_detector(args.model)
    except Exception as e:
        msg = f"{type(e).__name__}: {e}".splitlines()[0][:300]
        gated = any(
            c in msg
            for c in (
                "401",
                "403",
                "gated",
                "restricted",
                "awaiting",
                "access to model",
                "authorized",
                "accept",
            )
        )
        status = "GATED/license-not-accepted" if gated else "LOAD_FAILED"
        print(f"[{args.tag}] {status}: {msg}", flush=True)
        (OUTDIR / f"{args.tag}.ERROR").write_text(f"{status}: {msg}\n")
        return
    print(f"[{args.tag}] loaded; injection score = {desc}; max_len={maxlen}", flush=True)

    rows = [json.loads(l) for l in CACHE.open()]
    scores = score_texts([r["text"] for r in rows], tok, model, inj_fn, maxlen, args.batch_size)
    outpath = OUTDIR / f"{args.tag}.jsonl"
    with outpath.open("w") as f:
        for r, s in zip(rows, scores):
            f.write(json.dumps({"id": r["id"], "score": round(100.0 * float(s), 3)}) + "\n")
    print(f"[{args.tag}] DONE scored={len(rows)} -> {outpath}", flush=True)


if __name__ == "__main__":
    main()
