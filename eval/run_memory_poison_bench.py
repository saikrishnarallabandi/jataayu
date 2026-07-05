#!/usr/bin/env python3
"""
Jataayu on memory read/write poisoning (A6) — the persistent-memory surface.

Memory poisoning is the delayed-injection threat: untrusted content is written
into an agent's long-term memory on one turn, sits there benignly, and is
silently recalled into context on a LATER turn — where its embedded instruction
finally fires. jataayu screens this surface at BOTH ends:

  * jataayu_check_memory_write(text)  — screen at STORE time (surface memory-write)
  * jataayu_check_memory_read(text)   — screen at RECALL time (surface memory-read)

This harness runs a balanced, deterministically-generated corpus
(eval/data/memory_poison_v1.jsonl, built by gen_memory_poison_v1.py under a fixed
SEED) through BOTH entry points and answers:

  - Of poisoned memories, how many does the store-time / recall-time screen FLAG,
    broken out by subclass (direct-instruction / deferred-sleeper / encoded)?
  - What is the false-BLOCK rate on ordinary and tricky-but-benign memories?
  - Do write-time and read-time detection actually differ?

Reports precision / recall / FPR / F1 at jataayu's operating points for each
entry point, detection_by_subclass, benign false-block rate, latency, and an
explicit write-vs-read comparison. Fast path by default; --llm enables the slow
path (LLM judge) exactly as in run_injecagent_bench.py.

Usage:
  python3 eval/run_memory_poison_bench.py [--llm] [--workers N] [--limit N]
"""
import argparse, json, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import numpy as np

from jataayu import jataayu_check_memory_write, jataayu_check_memory_read
from jataayu.core import engine
from jataayu.guards.inbound import InboundGuard

# qwen3 "thinking" models burn num_predict on <think> and return empty content;
# force think:false so the JSON classifier prompt returns a verdict. (Same patch
# as run_injecagent_bench.py / run_slowpath_bench.py.)
_orig_ollama = engine.LLMBackend._call_ollama
def _patched_ollama(self, system_prompt, user_message, max_tokens):
    import requests
    resp = requests.post(
        f"{self.base_url}/api/chat",
        json={"model": self.model, "think": False,
              "messages": [{"role": "system", "content": system_prompt},
                           {"role": "user", "content": user_message}],
              "stream": False, "options": {"num_predict": max_tokens}},
        timeout=180)
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()
engine.LLMBackend._call_ollama = _patched_ollama

DATA = Path(__file__).parent / "data" / "memory_poison_v1.jsonl"
OUT = Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)

# Two entry points, each pinned to its own surface.
ENTRY_POINTS = {
    "write": ("memory-write", jataayu_check_memory_write),
    "read":  ("memory-read", jataayu_check_memory_read),
}

# jataayu's ThreatLevel score bands (see InboundGuard._score_to_level).
OP_POINTS = {
    "BLOCKED>=0.90": 0.90,
    "HIGH>=0.70": 0.70,
    "MEDIUM>=0.45": 0.45,
    "LOW>=0.20": 0.20,
}

POISON_SUBCLASSES = ["direct-instruction", "deferred", "encoded"]


def load_rows(limit=None):
    rows = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]
    if limit:
        # Keep the class balance under --limit: interleave by label.
        pos = [r for r in rows if r["label"] == 1][:limit]
        neg = [r for r in rows if r["label"] == 0][:limit]
        rows = pos + neg
    return rows


def _score_one(fn, surface, text, use_llm):
    t0 = time.perf_counter()
    if use_llm:
        # llm_threshold=0.0 => LLM judges every item (fast path still short-circuits
        # >=0.9). Per-thread guard; compiled patterns are module-level. Matches the
        # slow-path ceiling methodology used by the other harnesses.
        for attempt in range(3):
            try:
                g = InboundGuard(use_llm=True, llm_threshold=0.0)
                r = g.check(text or "", surface=surface)
                return float(r.risk_score), (time.perf_counter() - t0) * 1000
            except Exception:
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                res = fn(text or "", use_llm=False)
                return float(res["risk_score"]), (time.perf_counter() - t0) * 1000
    res = fn(text or "", use_llm=False)
    return float(res["risk_score"]), (time.perf_counter() - t0) * 1000


def score(rows, surface, fn, use_llm, workers=1):
    if workers <= 1:
        out = [_score_one(fn, surface, r["text"], use_llm) for r in rows]
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            out = list(ex.map(lambda r: _score_one(fn, surface, r["text"], use_llm), rows))
    scores = np.array([s for s, _ in out])
    lat = np.array([l for _, l in out])
    return scores, lat


def metrics_at(y_true, y_score, thr):
    y_pred = (y_score >= thr).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return dict(threshold=thr, tp=tp, fp=fp, tn=tn, fn=fn,
                precision=round(prec, 4), recall=round(rec, 4),
                fpr=round(fpr, 4), f1=round(f1, 4))


def detection_of(rows, scores, thr, mask):
    """Detection rate on the poison subset selected by mask, at threshold."""
    idx = [i for i, r in enumerate(rows) if mask(r) and r["label"] == 1]
    if not idx:
        return None
    caught = sum(1 for i in idx if scores[i] >= thr)
    return dict(n=len(idx), caught=caught, detection_rate=round(caught / len(idx), 4))


def false_block_of(rows, scores, thr, mask):
    """False-block rate on the benign subset selected by mask, at threshold."""
    idx = [i for i, r in enumerate(rows) if mask(r) and r["label"] == 0]
    if not idx:
        return None
    blocked = sum(1 for i in idx if scores[i] >= thr)
    return dict(n=len(idx), blocked=blocked, false_block_rate=round(blocked / len(idx), 4))


def build_report(rows, y_true, scores, lat):
    rep = {
        "latency_ms": {"mean": round(float(lat.mean()), 4),
                       "p50": round(float(np.percentile(lat, 50)), 4),
                       "p99": round(float(np.percentile(lat, 99)), 4)},
        "operating_points": {name: metrics_at(y_true, scores, thr)
                             for name, thr in OP_POINTS.items()},
        "detection_by_subclass": {},
        "false_block_by_split": {},
    }
    for thr_name, thr in OP_POINTS.items():
        rep["detection_by_subclass"][thr_name] = {
            "overall": detection_of(rows, scores, thr, lambda r: True),
            **{sub: detection_of(rows, scores, thr, lambda r, s=sub: r["subclass"] == s)
               for sub in POISON_SUBCLASSES},
        }
        rep["false_block_by_split"][thr_name] = {
            "overall": false_block_of(rows, scores, thr, lambda r: True),
            "ordinary": false_block_of(rows, scores, thr, lambda r: r["label"] == 0 and not r["tricky"]),
            "tricky": false_block_of(rows, scores, thr, lambda r: r["label"] == 0 and r["tricky"]),
        }
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="enable slow path (LLM judge)")
    ap.add_argument("--workers", type=int, default=1, help="concurrent LLM requests")
    ap.add_argument("--limit", type=int, default=None, help="cap rows per class (smoke test)")
    args = ap.parse_args()

    rows = load_rows(args.limit)
    y_true = np.array([r["label"] for r in rows])
    n_pos, n_neg = int(y_true.sum()), int((y_true == 0).sum())
    path = "slowpath" if args.llm else "fastpath"
    by_sub = {s: sum(r["subclass"] == s for r in rows) for s in POISON_SUBCLASSES}
    print(f"[MemoryPoison/{path}] {len(rows)} memories | poison={n_pos} benign={n_neg} | {by_sub}")

    result = {
        "benchmark": "Memory read/write poisoning (A6) — delayed injection via persistent agent memory",
        "path": path,
        "corpus": {"file": str(DATA.name), "generator": "gen_memory_poison_v1.py",
                   "n_total": len(rows), "n_poison": n_pos, "n_benign": n_neg,
                   "poison_by_subclass": by_sub},
        "entry_points": {},
    }

    per_ep_scores = {}
    for ep_name, (surface, fn) in ENTRY_POINTS.items():
        scores, lat = score(rows, surface, fn, args.llm, workers=args.workers)
        per_ep_scores[ep_name] = scores
        rep = build_report(rows, y_true, scores, lat)
        rep["api"] = f"jataayu_check_memory_{ep_name} (surface={surface})"
        result["entry_points"][ep_name] = rep
        print(f"  {ep_name:5s}: "
              + " | ".join(f"{n}=R{rep['detection_by_subclass'][n]['overall']['detection_rate']:.2f}"
                           f"/FPR{rep['operating_points'][n]['fpr']:.2f}"
                           for n in OP_POINTS))

    # --- write-vs-read comparison ---
    w, r = per_ep_scores["write"], per_ep_scores["read"]
    diffs = np.abs(w - r)
    n_diff = int((diffs > 1e-9).sum())
    disagreements = [
        {"id": rows[i]["id"], "subclass": rows[i]["subclass"], "label": rows[i]["label"],
         "write_score": round(float(w[i]), 3), "read_score": round(float(r[i]), 3),
         "text": rows[i]["text"][:120]}
        for i in range(len(rows)) if diffs[i] > 1e-9
    ]
    result["write_vs_read"] = {
        "identical": n_diff == 0,
        "n_rows_differing": n_diff,
        "max_abs_score_delta": round(float(diffs.max()), 4),
        "mean_abs_score_delta": round(float(diffs.mean()), 6),
        "note": ("Store-time and recall-time screens route through the same engine "
                 "and both surfaces carry the same 1.1 risk multiplier, so per-row "
                 "scores are identical on the fast path — the defense is symmetric: "
                 "whatever is caught on recall is equally caught on store, and vice "
                 "versa." if n_diff == 0 else
                 "Scores diverge (expected only under the LLM slow path, whose "
                 "sampling is nondeterministic)."),
        "disagreements": disagreements[:20],
    }

    fn_out = OUT / ("memory_poison_v1.json" if not args.llm else "memory_poison_v1_slowpath.json")
    fn_out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    print(f"\nwrote {fn_out}")


if __name__ == "__main__":
    main()
