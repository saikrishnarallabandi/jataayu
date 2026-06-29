#!/usr/bin/env python3
"""
Jataayu slow-path (fast regex + LLM judge) benchmark.

Shows the two-path architecture as a tunable tradeoff: turning the LLM slow-path
on for every item (llm_threshold=0.0) vs the fast-path-only regex baseline.
Reports precision / recall / FPR / F1 / latency so the talk can state, honestly,
exactly what the LLM layer buys and what it costs.

Concurrency: ollama serves requests in parallel, so we hit one endpoint with a
thread pool. Point --host/--model at any tailnet ollama (judith, dgx-pavan).

  python run_slowpath_bench.py --host http://localhost:11434 --model qwen3:8b --workers 6
"""
import argparse, json, time, os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
from datasets import load_dataset, concatenate_datasets
from sklearn.metrics import roc_auc_score, average_precision_score

import jataayu.core.engine as engine
from jataayu.guards.inbound import InboundGuard

OUT = Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)

# --- Fix: thinking models (qwen3) burn num_predict on <think> and return empty
# content. Pass think:false so the JSON classifier prompt returns a verdict.
_orig_ollama = engine.LLMBackend._call_ollama
def _patched_ollama(self, system_prompt, user_message, max_tokens):
    import requests
    resp = requests.post(
        f"{self.base_url}/api/chat",
        json={"model": self.model, "think": False,
              "messages": [{"role": "system", "content": system_prompt},
                           {"role": "user", "content": user_message}],
              "stream": False, "options": {"num_predict": max_tokens}},
        timeout=120)
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()
engine.LLMBackend._call_ollama = _patched_ollama


def load_deepset():
    ds = load_dataset("deepset/prompt-injections")
    rows = concatenate_datasets([ds["train"], ds["test"]])
    return [(r["text"], int(r["label"])) for r in rows]


def metrics_at(y_true, y_score, thr):
    y_pred = (y_score >= thr).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum()); fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum()); fn = int(((y_pred == 0) & (y_true == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return dict(threshold=thr, tp=tp, fp=fp, tn=tn, fn=fn,
                precision=round(prec, 4), recall=round(rec, 4),
                fpr=round(fpr, 4), f1=round(f1, 4))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--surface", default="unknown")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    os.environ["JATAAYU_LLM_BACKEND"] = "ollama"
    os.environ["JATAAYU_LLM_MODEL"] = args.model
    os.environ["JATAAYU_LLM_BASE_URL"] = args.host

    rows = load_deepset()
    if args.limit:
        # balanced subset
        pos = [r for r in rows if r[1] == 1][: args.limit // 2]
        neg = [r for r in rows if r[1] == 0][: args.limit // 2]
        rows = pos + neg
    y_true = np.array([l for _, l in rows])
    print(f"slow-path: {len(rows)} rows ({int(y_true.sum())} inj / {int((y_true==0).sum())} benign) "
          f"model={args.model} host={args.host} workers={args.workers}")

    # llm_threshold=0.0 => LLM judges every item; fast-path still short-circuits >=0.9
    def classify(idx_text):
        idx, (text, _) = idx_text
        g = InboundGuard(use_llm=True, llm_threshold=0.0)  # per-thread (compiled patterns are module-level)
        t0 = time.perf_counter()
        r = g.check(text or "", surface=args.surface)
        return idx, float(r.risk_score), bool(r.llm_used), (time.perf_counter() - t0) * 1000

    scores = np.zeros(len(rows)); llm_used = np.zeros(len(rows)); lat = np.zeros(len(rows))
    t_start = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(classify, (i, rt)) for i, rt in enumerate(rows)]
        done = 0
        for f in as_completed(futs):
            idx, sc, used, ms = f.result()
            scores[idx] = sc; llm_used[idx] = used; lat[idx] = ms
            done += 1
            if done % 50 == 0:
                print(f"  {done}/{len(rows)}  elapsed {time.time()-t_start:.0f}s")
    wall = time.time() - t_start

    result = {
        "mode": "fast+llm slow-path (llm_threshold=0.0)",
        "dataset": "deepset/prompt-injections", "surface": args.surface,
        "model": args.model, "host": args.host, "workers": args.workers,
        "n_total": len(rows), "n_injection": int(y_true.sum()), "n_benign": int((y_true == 0).sum()),
        "wall_seconds": round(wall, 1),
        "llm_used_frac": round(float(llm_used.mean()), 3),
        "latency_ms": {"mean": round(float(lat.mean()), 1), "p50": round(float(np.percentile(lat, 50)), 1),
                       "p99": round(float(np.percentile(lat, 99)), 1)},
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4),
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4),
        "operating_points": {n: metrics_at(y_true, scores, t)
                             for n, t in {"BLOCKED>=0.90": 0.90, "HIGH>=0.70": 0.70,
                                          "MEDIUM>=0.45": 0.45, "LOW>=0.20": 0.20}.items()},
    }
    fn = OUT / f"deepset_slowpath_{args.model.replace(':','_').replace('/','_')}.json"
    fn.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2)); print(f"\nwrote {fn}")


if __name__ == "__main__":
    main()
