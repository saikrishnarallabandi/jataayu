#!/usr/bin/env python3
"""
Jataayu egress-channel benchmark (A4) — the zero-click exfiltration surface.

Scores a deterministic PoC corpus through ``jataayu_check_egress`` and reports,
honestly and by channel, whether jataayu catches the data-carrying URL / auto-
fetched image class (EchoLeak / AgentFlayer / Notion) while letting legitimate
links and allowlisted images through.

Metrics:
  * RECALL (channel caught)      = of exfil rows, fraction NOT SAFE (WARN|BLOCK).
                                   The guard neutralizes the URL at WARN and hard-
                                   blocks beacons/secrets at BLOCK, so "caught"
                                   is the not-SAFE rate; block-rate is reported
                                   separately.
  * BLOCK-RATE                   = of exfil rows, fraction at status BLOCK
                                   (beacon hosts + confirmed-secret exfil).
  * BENIGN-PASS / FALSE-BLOCK    = of benign rows, fraction SAFE / not-SAFE.
  * CONFIRMED-EXFIL DETECTION    = of secret-riding rows, fraction caught, and
                                   fraction flagged with the confirmed-secret
                                   reason (max score).
  * TEXT-PRESERVATION            = of caught rows, fraction whose human-readable
                                   text survived in `redacted` while the
                                   offending URL was removed.

Broken down by channel: data-url / image / relay. Deterministic; no LLM.

Generate the corpus with ``python benchmarks/data/gen_egress_v1.py``.

Usage:
  python benchmarks/run_egress_bench.py
  python benchmarks/run_egress_bench.py --surface github-comment --json
  python benchmarks/run_egress_bench.py --repeat 10          # median-of-10 latency
"""

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from bench_latency import median_of_runs, summarize  # noqa: E402

from jataayu import jataayu_check_egress  # noqa: E402

DATA = HERE / "data" / "egress_v1.jsonl"
OUT_DIR = HERE / "results"
OUT_DIR.mkdir(exist_ok=True)

CHANNELS = ("data-url", "image", "relay")


def load(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def score(rec, surface):
    t0 = time.perf_counter()
    r = jataayu_check_egress(
        rec["text"],
        surface=surface,
        allowed_domains=rec.get("allowed_domains") or None,
        context_secrets=rec.get("context_secrets") or None,
    )
    return r, (time.perf_counter() - t0) * 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(DATA))
    ap.add_argument(
        "--surface", default="github-comment", help="target surface (recorded on the result)"
    )
    ap.add_argument("--out", default=str(OUT_DIR / "egress_v1.json"))
    ap.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="score the corpus N times and report the median of the per-run "
        "latency statistics (detection is deterministic and unaffected)",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")

    rows = load(args.data)
    pos = [r for r in rows if r["is_exfil"]]
    neg = [r for r in rows if not r["is_exfil"]]
    print(
        f"[egress] {len(rows)} records | exfil={len(pos)} benign={len(neg)} "
        f"| surface={args.surface}"
    )

    # with --repeat the corpus is scored again for the timing only; the guard is
    # deterministic, so every pass produces the same decisions.
    runs = []
    for _ in range(args.repeat):
        lat = []
        scored = []
        for rec in rows:
            r, dt = score(rec, args.surface)
            lat.append(dt)
            scored.append((rec, r))
        runs.append(summarize(lat))

    def not_safe(r):
        return r["status"] in ("WARN", "BLOCK")

    def blocked(r):
        return r["status"] == "BLOCK"

    def text_preserved(rec, r):
        """Human text kept AND offending URL removed in the redacted output."""
        red = r["redacted"]
        if red is None:
            return False
        human_ok = rec["human_marker"] in red
        url_gone = rec["url_marker"] not in red
        return human_ok and url_gone

    # ---- overall detection (exfil = positive) -----------------------------
    tp = sum(1 for rec, r in scored if rec["is_exfil"] and not_safe(r))
    fn = len(pos) - tp
    fp = sum(1 for rec, r in scored if not rec["is_exfil"] and not_safe(r))
    tn = len(neg) - fp
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec_ = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * rec_ / (prec + rec_) if (prec + rec_) else 0.0
    n_block = sum(1 for rec, r in scored if rec["is_exfil"] and blocked(r))

    overall = {
        "n_exfil": len(pos),
        "n_benign": len(neg),
        "recall_caught": round(rec_, 4),  # not-SAFE on exfil
        "block_rate": round(n_block / len(pos), 4) if pos else None,
        "precision": round(prec, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "benign_pass_rate": round(tn / len(neg), 4) if neg else None,
        "benign_false_block_rate": round(fp / len(neg), 4) if neg else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }

    # ---- by channel -------------------------------------------------------
    by_channel = {}
    for ch in CHANNELS:
        sub = [(rec, r) for rec, r in scored if rec["channel"] == ch]
        if not sub:
            continue
        caught = sum(1 for rec, r in sub if not_safe(r))
        blk = sum(1 for rec, r in sub if blocked(r))
        preserved = sum(1 for rec, r in sub if not_safe(r) and text_preserved(rec, r))
        by_channel[ch] = {
            "n": len(sub),
            "recall_caught": round(caught / len(sub), 4),
            "block_rate": round(blk / len(sub), 4),
            "text_preserved_of_caught": round(preserved / caught, 4) if caught else None,
            "missed": [rec["id"] for rec, r in sub if not not_safe(r)],
        }

    # ---- confirmed-exfil (secret riding the URL) --------------------------
    sec = [(rec, r) for rec, r in scored if rec.get("has_secret")]
    sec_caught = sum(1 for rec, r in sec if not_safe(r))
    sec_confirmed = sum(1 for rec, r in sec if "known sensitive value" in (r["findings"] or ""))
    confirmed_exfil = {
        "n_secret_riding": len(sec),
        "caught": sec_caught,
        "recall": round(sec_caught / len(sec), 4) if sec else None,
        "flagged_as_confirmed_secret": sec_confirmed,
        "confirmed_reason_rate": round(sec_confirmed / len(sec), 4) if sec else None,
    }

    # ---- text preservation (all caught positives) -------------------------
    caught_pos = [(rec, r) for rec, r in scored if rec["is_exfil"] and not_safe(r)]
    preserved_all = sum(1 for rec, r in caught_pos if text_preserved(rec, r))
    text_preservation = {
        "n_caught": len(caught_pos),
        "preserved": preserved_all,
        "rate": round(preserved_all / len(caught_pos), 4) if caught_pos else None,
        "note": "human_marker present AND url_marker removed in redacted output",
    }

    # ---- benign that were (incorrectly) altered ---------------------------
    benign_altered = []
    for rec, r in scored:
        if not rec["is_exfil"] and not_safe(r):
            benign_altered.append(
                {
                    "id": rec["id"],
                    "text": rec["text"],
                    "status": r["status"],
                    "findings": r["findings"],
                }
            )

    result = {
        "benchmark": "Jataayu egress-channel (EchoLeak / AgentFlayer / Notion class)",
        "api": "jataayu_check_egress (deterministic, no LLM)",
        "surface": args.surface,
        "corpus": str(args.data),
        "overall": overall,
        "by_channel": by_channel,
        "confirmed_exfil": confirmed_exfil,
        "text_preservation": text_preservation,
        "benign_false_blocks": benign_altered,
        "repeat": args.repeat,
        "latency_ms": median_of_runs(runs),
        "notes": [
            "Recall = not-SAFE rate (the guard neutralizes at WARN and hard-blocks "
            "beacons/secrets at BLOCK). BLOCK is reserved for exfil-beacon hosts and "
            "confirmed-secret URLs; data-carrying links/images to other external "
            "hosts are WARN (URL neutralized, human text kept).",
        ],
    }

    Path(args.out).write_text(json.dumps(result, indent=2))

    # ---- console summary --------------------------------------------------
    o = overall
    print(
        f"\nOverall: recall(caught)={o['recall_caught']:.3f} block_rate={o['block_rate']:.3f} "
        f"P={o['precision']:.3f} FPR={o['fpr']:.3f} F1={o['f1']:.3f}"
    )
    print(
        f"Benign:  pass_rate={o['benign_pass_rate']:.3f} "
        f"false_block={o['benign_false_block_rate']:.3f}"
    )
    ce = confirmed_exfil
    print(
        f"Confirmed-exfil (secret in URL): recall={ce['recall']} "
        f"confirmed_reason_rate={ce['confirmed_reason_rate']} (n={ce['n_secret_riding']})"
    )
    print(
        f"Text-preservation (of caught): {text_preservation['rate']} "
        f"({text_preservation['preserved']}/{text_preservation['n_caught']})"
    )
    print(f"\n{'channel':10} {'n':>3} {'recall':>7} {'block':>7} {'text-kept':>10} {'missed'}")
    for ch, m in by_channel.items():
        tk = (
            "-" if m["text_preserved_of_caught"] is None else f"{m['text_preserved_of_caught']:.3f}"
        )
        print(
            f"{ch:10} {m['n']:>3} {m['recall_caught']:>7.3f} {m['block_rate']:>7.3f} "
            f"{tk:>10} {m['missed'] or ''}"
        )
    if benign_altered:
        print(f"\nWARNING — benign false-blocks: {[b['id'] for b in benign_altered]}")
    over = f" (median of {args.repeat} runs)" if args.repeat > 1 else ""
    print(
        f"\nlatency: mean {result['latency_ms']['mean']}ms  "
        f"p99 {result['latency_ms']['p99']}ms{over}"
    )
    print(f"wrote {args.out}")

    if args.json:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
