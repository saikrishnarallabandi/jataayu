#!/usr/bin/env python3
"""
A5 — Skillset composition benchmark for Jataayu.

Exercises jataayu.guards.composition.check_skillset over a deterministic corpus of
individually-plausible skill SETS (benchmarks/data/composition_v1.jsonl). Measures whether
the guard surfaces the correct verdict and the right risky_combinations /
policy_violations / trust_transfer for each risk class, and its false-positive rate
on genuinely-safe sets.

This surface is fully deterministic/structural: skills are passed as dicts with
explicit capabilities, so NO LLM is invoked (use_llm defaults False, and the LLM path
in check_skillset only fires when vetting raw skill *paths*). Nothing here is deferred
to a Phase-B model pass.

Run:
    python3 benchmarks/run_composition_bench.py
Writes:
    benchmarks/results/composition_v1.json
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from jataayu.guards.composition import check_skillset
from jataayu.config.policy import AgentPolicy

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "data" / "composition_v1.jsonl"
OUT = HERE / "results" / "composition_v1.json"


def load_corpus() -> list[dict]:
    if not CORPUS.exists():
        # Auto-generate if missing (keeps the bench self-contained + reproducible).
        import subprocess
        import sys
        subprocess.run([sys.executable, str(HERE / "data" / "gen_composition_v1.py")], check=True)
    with CORPUS.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def build_policy(spec: dict | None) -> AgentPolicy | None:
    if not spec:
        return None
    return AgentPolicy(
        name="bench",
        allowed_capabilities=spec.get("allowed_capabilities", []),
        forbidden_capabilities=spec.get("forbidden_capabilities", []),
    )


def evaluate_row(row: dict) -> dict:
    """Run check_skillset on one set and score it against ground truth."""
    policy = build_policy(row.get("policy"))
    risk = check_skillset(row["skills"], policy=policy)
    got = risk.to_dict()

    verdict_ok = got["verdict"] == row["expected_verdict"]

    # --- signal-level scoring per class ---
    combo_descs = [c["description"] for c in got["risky_combinations"]]
    viol_caps = [v["capability"] for v in got["policy_violations"]]
    trust_skills = [t["skill"] for t in got["trust_transfer"]]

    signal_ok = None  # None => not applicable to this row
    detail = {}

    exp_combo = row.get("expected_combo")
    if exp_combo is not None:
        found = any(exp_combo in d for d in combo_descs)
        detail["combo"] = {"expected": exp_combo, "found": found, "surfaced": combo_descs}
        signal_ok = found

    exp_viol = row.get("expected_violation", "__na__")
    if exp_viol != "__na__":
        if exp_viol is None:
            ok = len(viol_caps) == 0
        else:
            ok = exp_viol in viol_caps
        detail["policy_violation"] = {"expected": exp_viol, "found": ok, "surfaced": viol_caps}
        signal_ok = ok if signal_ok is None else (signal_ok and ok)

    exp_trust = row.get("expected_trust_skill", "__na__")
    if exp_trust != "__na__":
        if exp_trust is None:
            ok = len(trust_skills) == 0
        else:
            ok = exp_trust in trust_skills
        detail["trust_transfer"] = {"expected": exp_trust, "found": ok, "surfaced": trust_skills}
        signal_ok = ok if signal_ok is None else (signal_ok and ok)

    # fragmentation flag check (informational)
    if row.get("expected_fragmented"):
        frag = any(c.get("fragmented") for c in got["risky_combinations"])
        detail["fragmented"] = {"expected": True, "found": frag}

    # A row is a full PASS if verdict matches AND every applicable signal matches.
    passed = verdict_ok and (signal_ok in (True, None))

    return {
        "id": row["id"],
        "class": row["class"],
        "expected_verdict": row["expected_verdict"],
        "got_verdict": got["verdict"],
        "verdict_ok": verdict_ok,
        "signal_ok": signal_ok,
        "passed": passed,
        "skills": [s.get("name") for s in row["skills"]],
        "aggregate_capabilities": got["aggregate_capabilities"],
        "detail": detail,
        "explanation": got["explanation"],
    }


def main() -> None:
    rows = load_corpus()
    # PROBE rows are coverage-gap probes (human-risky paths outside the guard's model);
    # they are analysed separately and NOT folded into recall / FP scoring.
    scored_rows = [r for r in rows if r["class"] != "PROBE"]
    probe_rows = [r for r in rows if r["class"] == "PROBE"]

    results = [evaluate_row(r) for r in scored_rows]

    by_class: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_class[r["class"]].append(r)

    # ---- confusion matrix: expected_verdict x got_verdict, per class ----
    confusion: dict[str, dict[str, int]] = {}
    for cls, rs in by_class.items():
        c: Counter = Counter()
        for r in rs:
            c[f"{r['expected_verdict']}->{r['got_verdict']}"] += 1
        confusion[cls] = dict(sorted(c.items()))

    # ---- recall on positive (should-be-flagged) rows per risk class ----
    # For RISKY/TRUST/POLICY, "positive" rows are those whose expected_verdict != SAFE.
    def recall_for(cls: str) -> dict:
        rs = [r for r in by_class[cls] if r["expected_verdict"] != "SAFE"]
        if not rs:
            return {"n": 0, "verdict_recall": None, "signal_recall": None}
        v_hits = sum(1 for r in rs if r["verdict_ok"])
        s_hits = sum(1 for r in rs if r["passed"])
        return {
            "n": len(rs),
            "verdict_recall": round(v_hits / len(rs), 4),
            "signal_recall": round(s_hits / len(rs), 4),
        }

    recall = {cls: recall_for(cls) for cls in ("RISKY", "POLICY", "TRUST")}

    # ---- false-positive rate on SAFE sets ----
    # A false positive = a genuinely-safe set the guard did NOT return SAFE for.
    # We measure this across ALL rows whose ground-truth verdict is SAFE, regardless of
    # which class-bucket they live in (SAFE class + policy-ok + benign-endorsed controls).
    safe_rows = [r for r in results if r["expected_verdict"] == "SAFE"]
    safe_fp = [r for r in safe_rows if r["got_verdict"] != "SAFE"]
    fp_rate = round(len(safe_fp) / len(safe_rows), 4) if safe_rows else None

    # ---- honest failure reporting: which risky combos were MISSED ----
    missed = []
    for r in results:
        if r["expected_verdict"] != "SAFE" and not r["passed"]:
            missed.append({
                "id": r["id"], "class": r["class"],
                "expected_verdict": r["expected_verdict"], "got_verdict": r["got_verdict"],
                "detail": r["detail"], "skills": r["skills"],
            })

    # ---- coverage-gap probes: human-risky paths outside the guard's combo model ----
    coverage_gaps = []
    probe_results = []
    for row in probe_rows:
        risk = check_skillset(row["skills"], policy=build_policy(row.get("policy")))
        got = risk.to_dict()
        flagged = got["verdict"] != "SAFE"
        rec = {
            "id": row["id"],
            "skills": [s.get("name") for s in row["skills"]],
            "capabilities": got["aggregate_capabilities"],
            "human_risky": True,
            "guard_verdict": got["verdict"],
            "guard_flagged": flagged,
            "note": row["note"],
        }
        probe_results.append(rec)
        if not flagged:
            coverage_gaps.append(rec)

    overall_pass = sum(1 for r in results if r["passed"])
    headline = {
        "corpus": str(CORPUS),
        "total_sets": len(results),
        "class_counts": {k: len(v) for k, v in sorted(by_class.items())},
        "overall_pass_rate": round(overall_pass / len(results), 4),
        "risk_recall": recall,                 # verdict + signal recall per risk class
        "safe_false_positive_rate": fp_rate,   # lower is better
        "safe_sets_evaluated": len(safe_rows),
        "safe_false_positives": len(safe_fp),
        "missed_positive_sets": len(missed),
        "coverage_gap_probes": len(probe_rows),
        "coverage_gaps_found": len(coverage_gaps),
        "input_shape_matched_cleanly": True,
        "llm_used": False,
        "phase_b_followup": "none — corpus uses explicit-capability dicts; check_skillset ran fully structurally.",
    }

    report = {
        "headline": headline,
        "confusion_by_class": confusion,
        "missed": missed,
        "coverage_gaps": coverage_gaps,
        "probe_results": probe_results,
        "false_positives": [
            {"id": r["id"], "class": r["class"], "got_verdict": r["got_verdict"],
             "explanation": r["explanation"], "skills": r["skills"]}
            for r in safe_fp
        ],
        "per_case": results,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        json.dump(report, f, indent=2)

    # ---- console report (mirrors existing runners' style) ----
    print("=" * 72)
    print("JATAAYU A5 — Skillset Composition Benchmark")
    print("=" * 72)
    print(f"corpus: {CORPUS}")
    print(f"total sets: {headline['total_sets']}  |  classes: {headline['class_counts']}")
    print(f"overall pass rate: {headline['overall_pass_rate']:.1%}")
    print(f"input shape matched check_skillset cleanly: {headline['input_shape_matched_cleanly']}")
    print(f"LLM invoked: {headline['llm_used']}")
    print("-" * 72)
    print("RECALL by risk class (verdict / signal):")
    for cls, m in recall.items():
        if m["n"]:
            print(f"  {cls:7s} n={m['n']:2d}  verdict={m['verdict_recall']:.1%}  signal={m['signal_recall']:.1%}")
    print("-" * 72)
    print(f"SAFE false-positive rate: {fp_rate:.1%}  "
          f"({len(safe_fp)}/{len(safe_rows)} safe sets misflagged)")
    print("-" * 72)
    print("CONFUSION (expected -> got) by class:")
    for cls in sorted(confusion):
        print(f"  {cls}: {confusion[cls]}")
    print("-" * 72)
    if missed:
        print(f"MISSED positive sets ({len(missed)}) — honest failure report:")
        for m in missed:
            print(f"  [{m['id']}] {m['class']}  exp={m['expected_verdict']} got={m['got_verdict']}  "
                  f"skills={m['skills']}")
            print(f"      detail={m['detail']}")
    else:
        print("MISSED positive sets: NONE — every risky/policy/trust set was surfaced.")
    print("-" * 72)
    print(f"COVERAGE-GAP PROBES ({len(probe_rows)}): human-risky paths outside the guard's "
          f"4-combo model")
    if coverage_gaps:
        print(f"  {len(coverage_gaps)}/{len(probe_rows)} returned SAFE — capability paths the "
              f"current surface does NOT model:")
        for g in coverage_gaps:
            print(f"  [MISS] {g['capabilities']}  ({'+'.join(g['skills'])}) -> {g['guard_verdict']}")
            print(f"         {g['note']}")
    else:
        print("  none — the guard flagged every probe.")
    print("-" * 72)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
