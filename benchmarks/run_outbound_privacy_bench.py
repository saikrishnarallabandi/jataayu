#!/usr/bin/env python3
"""
Jataayu outbound / PII-privacy benchmark — "what goes OUT" surface.

Answers two honest questions about ``jataayu_check_outbound`` on labeled PII:

  1. DETECTION — of PII-bearing messages, how many are flagged (WARN/BLOCK),
     and at what false-positive cost on benign messages that must pass clean?
     Reported as precision / recall / FPR / F1, overall and per PII category,
     plus operating points over the raw risk score (parity with the other
     jataayu runners).

  2. REDACTION — of each labeled PII span, was the exact span value actually
     removed from ``redacted``? And on benign messages, how much clean text got
     over-redacted? Reported as span-removal recall per category and an
     over-redaction rate.

Corpus
------
Positives for the *public* PII types (email / phone / SSN / credit-card /
address / financial-account / credential) are drawn from
``gretelai/synthetic_pii_finance_multilingual`` (Apache-2.0 — the PREFERRED
primary source; a bounded, deterministic first-N sample of the English rows).
``ai4privacy/pii-masking-200k`` remains available via ``--source ai4privacy`` as
an eval-only reference (its license bars our training/derivative use). If the
public set will not download, the harness falls back to the curated
``standard_pii`` positives in ``benchmarks/data/outbound_privacy_v1.jsonl``.

Positives for the categories jataayu *uniquely* targets and that no public PII
set labels — contextual health, minors, relationships, financial disclosure,
credential leaks, protected names — always come from the curated
``jataayu_native`` split. Benign negatives always come from the curated
``benign`` split. Generate the curated file with
``python benchmarks/data/gen_outbound_privacy_v1.py``.

Honest scope note
-----------------
jataayu's outbound regex layer is designed for a *subset* of PII: it catches
emails, phones, SSNs (only when prefixed by "SSN"/"social security"),
credit-card numbers, street addresses and ZIPs, plus its distinctive contextual
categories and credential leaks. Names are caught ONLY via ``protected_names``.
Public-set label types like personal names, crypto/bank addresses, IPs, IMEIs,
VINs, dates and job info are OUT OF SCOPE by design — this harness reports them
in a separate ``out_of_scope`` bucket rather than pretending they count against
recall.

Deterministic and re-runnable. Fast path only (the outbound guard's regex layer;
no LLM).

Usage:
  python benchmarks/run_outbound_privacy_bench.py
  python benchmarks/run_outbound_privacy_bench.py --hf-limit 400 --surface public --json
  python benchmarks/run_outbound_privacy_bench.py --no-hf     # curated corpus only
  python benchmarks/run_outbound_privacy_bench.py --repeat 10 # median-of-10 latency
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from bench_latency import median_of_runs, summarize  # noqa: E402

from jataayu import jataayu_check_outbound  # noqa: E402

DATA = HERE / "data" / "outbound_privacy_v1.jsonl"
OUT_DIR = HERE / "results"
OUT_DIR.mkdir(exist_ok=True)

FLAG_STATUSES = {"WARN", "BLOCK"}

OP_POINTS = {
    "BLOCK>=0.90": 0.90,
    "WARN/HIGH>=0.70": 0.70,
    "MEDIUM>=0.45": 0.45,
    "LOW>=0.20": 0.20,
}

# --- ai4privacy label -> (jataayu category, in_scope) ----------------------
# in_scope = jataayu's outbound regex layer is *designed* to catch this type.
CATEGORY_MAP = {
    "EMAIL": ("email", True),
    "PHONENUMBER": ("phone", True),
    "SSN": ("ssn", True),
    "CREDITCARDNUMBER": ("credit_card", True),
    "STREET": ("address", True),
    "BUILDINGNUMBER": ("address", True),
    "SECONDARYADDRESS": ("address", True),
    "ZIPCODE": ("address", True),
    "ACCOUNTNUMBER": ("financial_account", True),
    "IBAN": ("financial_account", True),
    "BIC": ("financial_account", True),
    "MASKEDNUMBER": ("financial_account", True),
    # curated jataayu-native labels (always in scope — the point of the guard)
    "HEALTH": ("health", True),
    "MINOR": ("minors_info", True),
    "RELATIONSHIP": ("relationships", True),
    "FINANCIAL": ("financial", True),
    "CREDENTIAL": ("credential", True),
    "PROTECTED_NAME": ("name", True),
}
# Everything not listed above is out of scope by design.
OUT_OF_SCOPE_DEFAULT = ("out_of_scope", False)

# --- gretelai/synthetic_pii_finance_multilingual label -> (category, in_scope) ---
# gretel uses its own lowercase label vocabulary; map it onto the same jataayu
# categories as ai4privacy above. in_scope = jataayu's outbound regex is designed to
# catch this type. License: Apache-2.0 (training/derivative use permitted — this is the
# PREFERRED primary PII source; ai4privacy is eval-reference-only, its CC-BY-NC-style
# terms bar our training/derivative use).
GRETEL_CATEGORY_MAP = {
    "email": ("email", True),
    "phone_number": ("phone", True),
    "ssn": ("ssn", True),
    "credit_card_number": ("credit_card", True),
    "credit_card_security_code": ("credit_card", True),
    "street_address": ("address", True),
    "iban": ("financial_account", True),
    "bban": ("financial_account", True),
    "bank_routing_number": ("financial_account", True),
    "swift_bic_code": ("financial_account", True),
    "password": ("credential", True),
    "api_key": ("credential", True),
    "account_pin": ("credential", True),
    # explicit out-of-scope (jataayu does not target these; reported separately)
    "name": ("out_of_scope", False),
    "first_name": ("out_of_scope", False),
    "last_name": ("out_of_scope", False),
    "user_name": ("out_of_scope", False),
    "company": ("out_of_scope", False),
    "date": ("out_of_scope", False),
    "time": ("out_of_scope", False),
    "date_time": ("out_of_scope", False),
    "date_of_birth": ("out_of_scope", False),
    "passport_number": ("out_of_scope", False),
    "driver_license_number": ("out_of_scope", False),
    "customer_id": ("out_of_scope", False),
    "employee_id": ("out_of_scope", False),
    "ipv4": ("out_of_scope", False),
    "ipv6": ("out_of_scope", False),
    "local_latlng": ("out_of_scope", False),
}


def cat_for(label: str):
    return CATEGORY_MAP.get(label, OUT_OF_SCOPE_DEFAULT)


# --------------------------------------------------------------------------
# corpus loading
# --------------------------------------------------------------------------
def load_curated(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def load_hf_positives(limit):
    """Deterministic first-N English rows of ai4privacy/pii-masking-200k.

    Returns (rows, None) on success, or (None, reason) if unavailable.
    """
    try:
        from datasets import load_dataset
    except Exception as e:  # pragma: no cover
        return None, f"datasets import failed: {e}"
    try:
        ds = load_dataset("ai4privacy/pii-masking-200k", split="train", streaming=True)
    except Exception as e:
        return None, f"load_dataset failed: {type(e).__name__}: {str(e)[:160]}"

    rows = []
    try:
        for row in ds:
            if row.get("language") != "en":
                continue
            spans = []
            for s in row.get("privacy_mask", []):
                cat, in_scope = cat_for(s["label"])
                spans.append(
                    {
                        "value": s["value"],
                        "label": s["label"],
                        "category": cat,
                        "in_scope": in_scope,
                    }
                )
            rows.append(
                {
                    "id": f"ai4privacy-{row.get('id')}",
                    "text": row["source_text"],
                    "is_pii": True,
                    "spans": spans,
                    "protected_names": [],
                    "source": "ai4privacy",
                    "split": "standard_pii",
                }
            )
            if len(rows) >= limit:
                break
    except Exception as e:
        if not rows:
            return None, f"streaming failed: {type(e).__name__}: {str(e)[:160]}"
        # partial is fine — deterministic prefix
    return rows, None


def load_gretel_positives(limit):
    """Deterministic first-N English rows of gretelai/synthetic_pii_finance_multilingual
    (Apache-2.0; the PREFERRED primary PII source). Spans carry (start, end, label) only,
    so each span value is sliced from ``generated_text``.

    Returns (rows, None) on success, or (None, reason) if unavailable.
    """
    try:
        from datasets import load_dataset
    except Exception as e:  # pragma: no cover
        return None, f"datasets import failed: {e}"
    try:
        ds = load_dataset(
            "gretelai/synthetic_pii_finance_multilingual", split="test", streaming=True
        )
    except Exception as e:
        return None, f"load_dataset failed: {type(e).__name__}: {str(e)[:160]}"

    rows = []
    try:
        for row in ds:
            if row.get("language") != "English":
                continue
            text = row["generated_text"]
            try:
                raw_spans = json.loads(row["pii_spans"])
            except (TypeError, json.JSONDecodeError):
                raw_spans = []
            spans = []
            for s in raw_spans:
                value = text[s["start"] : s["end"]]
                if not value:
                    continue
                cat, in_scope = GRETEL_CATEGORY_MAP.get(s["label"], OUT_OF_SCOPE_DEFAULT)
                spans.append(
                    {"value": value, "label": s["label"], "category": cat, "in_scope": in_scope}
                )
            if not spans:
                continue
            rows.append(
                {
                    "id": f"gretel-{row.get('index')}",
                    "text": text,
                    "is_pii": True,
                    "spans": spans,
                    "protected_names": [],
                    "source": "gretelai",
                    "split": "standard_pii",
                }
            )
            if len(rows) >= limit:
                break
    except Exception as e:
        if not rows:
            return None, f"streaming failed: {type(e).__name__}: {str(e)[:160]}"
        # partial is fine — deterministic prefix
    return rows, None


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------
def score_record(rec, surface):
    t0 = time.perf_counter()
    r = jataayu_check_outbound(
        rec["text"],
        surface=surface,
        protected_names=rec.get("protected_names") or None,
        use_llm=False,
    )
    dt = (time.perf_counter() - t0) * 1000
    return r, dt


def prf(tp, fp, tn, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return dict(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=round(prec, 4),
        recall=round(rec, 4),
        fpr=round(fpr, 4),
        f1=round(f1, 4),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(DATA))
    ap.add_argument(
        "--surface", default="public", help="outbound surface (affects strictness); default public"
    )
    ap.add_argument(
        "--source",
        choices=["gretelai", "ai4privacy"],
        default="gretelai",
        help="public PII source for standard_pii positives. Default gretelai "
        "(Apache-2.0, preferred). ai4privacy is an eval-only reference "
        "(its license bars training/derivative use).",
    )
    ap.add_argument(
        "--hf-limit",
        type=int,
        default=400,
        help="max English public rows to sample (deterministic prefix)",
    )
    ap.add_argument(
        "--no-hf", action="store_true", help="skip the public dataset; use the curated corpus only"
    )
    ap.add_argument("--out", default=str(OUT_DIR / "outbound_privacy_v1.json"))
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

    curated = load_curated(args.data)
    benign = [r for r in curated if r["split"] == "benign"]
    native = [r for r in curated if r["split"] == "jataayu_native"]
    curated_std = [r for r in curated if r["split"] == "standard_pii"]

    # standard_pii positives: prefer the public set
    hf_reason = None
    if args.no_hf:
        std, corpus_source = curated_std, "curated (public set skipped via --no-hf)"
    else:
        if args.source == "gretelai":
            hf_rows, hf_reason = load_gretel_positives(args.hf_limit)
            public_label = "gretelai/synthetic_pii_finance_multilingual (Apache-2.0)"
        else:
            hf_rows, hf_reason = load_hf_positives(args.hf_limit)
            public_label = "ai4privacy/pii-masking-200k (eval-reference only)"
        if hf_rows:
            std, corpus_source = hf_rows, public_label
        else:
            std, corpus_source = (
                curated_std,
                f"curated fallback (public set unavailable: {hf_reason})",
            )

    records = std + native + benign
    print(
        f"[outbound-privacy] {len(records)} records | "
        f"standard_pii={len(std)} native={len(native)} benign={len(benign)} "
        f"| source={corpus_source} | surface={args.surface}"
    )

    # score everything; with --repeat the corpus is scored again for the timing only (the
    # fast path is deterministic, so every pass produces the same findings)
    runs = []
    for _ in range(args.repeat):
        lat = []
        scored = []  # (rec, api_result)
        for rec in records:
            r, dt = score_record(rec, args.surface)
            lat.append(dt)
            scored.append((rec, r))
        runs.append(summarize(lat))

    # ---- detection (status-based: flagged = WARN|BLOCK) -------------------
    def flagged(r):
        return r["status"] in FLAG_STATUSES

    pos = [(rec, r) for rec, r in scored if rec["is_pii"]]
    neg = [(rec, r) for rec, r in scored if not rec["is_pii"]]
    tp = sum(1 for _, r in pos if flagged(r))
    fn = len(pos) - tp
    fp = sum(1 for _, r in neg if flagged(r))
    tn = len(neg) - fp
    detection_status = prf(tp, fp, tn, fn)

    # detection split by corpus split (positives only, recall)
    detection_by_split = {}
    for split in ("standard_pii", "jataayu_native"):
        sub = [(rec, r) for rec, r in pos if rec["split"] == split]
        if sub:
            caught = sum(1 for _, r in sub if flagged(r))
            detection_by_split[split] = {
                "n": len(sub),
                "flagged": caught,
                "recall": round(caught / len(sub), 4),
            }

    # ---- operating points over raw risk score (parity w/ other runners) ---
    y = [(1 if rec["is_pii"] else 0, float(r["risk_score"])) for rec, r in scored]
    operating_points = {}
    for name, thr in OP_POINTS.items():
        _tp = sum(1 for lab, s in y if s >= thr and lab == 1)
        _fp = sum(1 for lab, s in y if s >= thr and lab == 0)
        _fn = sum(1 for lab, s in y if s < thr and lab == 1)
        _tn = sum(1 for lab, s in y if s < thr and lab == 0)
        operating_points[name] = {"threshold": thr, **prf(_tp, _fp, _tn, _fn)}

    # ---- per-category detection + redaction -------------------------------
    # detection: among positive messages containing >=1 span of category C,
    #            fraction flagged.
    # redaction: among all spans of category C, fraction whose value was removed
    #            from `redacted` (SAFE -> nothing removed).
    det_msgs = defaultdict(lambda: [0, 0])  # cat -> [flagged, total]
    red_spans = defaultdict(lambda: [0, 0])  # cat -> [removed, total]
    in_scope_flags = [0, 0]  # [flagged, total] messages w/ in-scope span
    for rec, r in pos:
        cats_in_msg = {sp["category"] for sp in rec["spans"]}
        is_flag = flagged(r)
        red = r["redacted"] if r["redacted"] is not None else rec["text"]
        for cat in cats_in_msg:
            det_msgs[cat][1] += 1
            if is_flag:
                det_msgs[cat][0] += 1
        # any in-scope span present? (spans carry a precomputed in_scope flag; fall
        # back to cat_for for curated rows that predate it)
        if any(sp.get("in_scope", cat_for(sp["label"])[1]) for sp in rec["spans"]):
            in_scope_flags[1] += 1
            if is_flag:
                in_scope_flags[0] += 1
        # span-level redaction
        for sp in rec["spans"]:
            red_spans[sp["category"]][1] += 1
            if sp["value"] not in red:
                red_spans[sp["category"]][0] += 1

    per_category = {}
    for cat in sorted(set(det_msgs) | set(red_spans)):
        dflag, dtot = det_msgs.get(cat, [0, 0])
        rrem, rtot = red_spans.get(cat, [0, 0])
        in_scope = any(v[0] == cat and v[1] for v in CATEGORY_MAP.values())
        per_category[cat] = {
            "in_scope": in_scope,
            "msgs_with_category": dtot,
            "detection_recall": round(dflag / dtot, 4) if dtot else None,
            "spans": rtot,
            "redaction_recall": round(rrem / rtot, 4) if rtot else None,
        }

    # ---- over-redaction on benign -----------------------------------------
    benign_flagged = sum(1 for _, r in neg if flagged(r))
    benign_changed = 0
    benign_examples = []
    for rec, r in neg:
        if r["redacted"] is not None and r["redacted"] != rec["text"]:
            benign_changed += 1
            if len(benign_examples) < 5:
                benign_examples.append(
                    {"text": rec["text"], "redacted": r["redacted"], "findings": r["findings"]}
                )

    over_redaction = {
        "n_benign": len(neg),
        "benign_pass_rate": round(1 - benign_flagged / len(neg), 4) if neg else None,
        "benign_false_block_rate": round(benign_flagged / len(neg), 4) if neg else None,
        "over_redaction_rate": round(benign_changed / len(neg), 4) if neg else None,
        "examples": benign_examples,
    }

    result = {
        "benchmark": "Jataayu outbound / PII-privacy — what-goes-OUT surface",
        "api": "jataayu_check_outbound (fast path, no LLM)",
        "corpus_source": corpus_source,
        "hf_unavailable_reason": hf_reason,
        "surface": args.surface,
        "n_total": len(records),
        "n_positive": len(pos),
        "n_benign": len(neg),
        "detection_status_based": {
            "decision": "flagged iff status in {WARN, BLOCK}",
            **detection_status,
        },
        "detection_by_split": detection_by_split,
        "detection_in_scope_only": {
            "n": in_scope_flags[1],
            "flagged": in_scope_flags[0],
            "recall": round(in_scope_flags[0] / in_scope_flags[1], 4)
            if in_scope_flags[1]
            else None,
            "note": "messages containing >=1 span jataayu is designed to catch",
        },
        "operating_points_by_risk_score": operating_points,
        "per_category": per_category,
        "over_redaction": over_redaction,
        "repeat": args.repeat,
        "latency_ms": median_of_runs(runs),
        "notes": [
            "Names are caught only via protected_names; generic personal names, "
            "crypto/bank addresses, IPs, IMEIs, VINs, dates and job info are "
            "out_of_scope by design and reported separately.",
            "SSN regex requires an 'SSN'/'social security' prefix; bare 9-digit "
            "numbers are not matched (see ssn category recall).",
            "Contextual categories (esp. health, base score 0.65) are DETECTED "
            "but fall below the 0.75 regex-redaction threshold, so they are "
            "flagged without their span being removed on the fast path.",
        ],
    }

    Path(args.out).write_text(json.dumps(result, indent=2))

    # ---- console summary --------------------------------------------------
    d = detection_status
    print(
        f"\nDetection (status WARN/BLOCK): "
        f"P={d['precision']:.3f} R={d['recall']:.3f} FPR={d['fpr']:.3f} F1={d['f1']:.3f} "
        f"(tp={d['tp']} fp={d['fp']} tn={d['tn']} fn={d['fn']})"
    )
    isc = result["detection_in_scope_only"]
    print(f"Detection (in-scope PII only): R={isc['recall']} over n={isc['n']}")
    ov = over_redaction
    print(
        f"Benign: pass_rate={ov['benign_pass_rate']} false_block={ov['benign_false_block_rate']} "
        f"over_redaction={ov['over_redaction_rate']}"
    )
    print(f"\n{'category':18} {'scope':>6} {'det-R':>7} {'red-R':>7} {'msgs':>5} {'spans':>6}")
    for cat, m in sorted(per_category.items(), key=lambda kv: (not kv[1]["in_scope"], kv[0])):
        dr = "-" if m["detection_recall"] is None else f"{m['detection_recall']:.3f}"
        rr = "-" if m["redaction_recall"] is None else f"{m['redaction_recall']:.3f}"
        print(
            f"{cat:18} {('in' if m['in_scope'] else 'OUT'):>6} {dr:>7} {rr:>7} "
            f"{m['msgs_with_category']:>5} {m['spans']:>6}"
        )
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
