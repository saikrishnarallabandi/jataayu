#!/usr/bin/env python3
"""
Jataayu effect-boundary EDGE-PATH eval — the two authorization paths with zero prior coverage.

Deterministic, no LLM, no dataset. Exercises the guarantees that the Tier 1/2 corpus scorers do
NOT touch, because they only look at the preview() decision:

  A. commit() token binding (effect_boundary.py:254). preview() an ALLOW action and issue a
     commit_token bound to the canonical request. Then:
       A1  commit with the SAME params            -> executor runs (happy path).
       A2  commit with MUTATED params             -> CommitRejected (post-authorization mutation).
       A3  commit a preview that was DENY/APPROVAL -> CommitRejected (no token was ever issued).

  B. Capability-policy DENY (effect_boundary.py:_decide step 1). Configure an AgentPolicy that
     FORBIDS a capability, then authorize a TRUSTED action that needs it. Capability isolation
     wins over provenance -> DENY, even though the input is trusted (would otherwise ALLOW).
       B1  forbidden capability (exec)            -> DENY at the capability step.
       B2  allowlist mode, capability not listed  -> DENY.
       B3  control: capability allowed            -> ALLOW (proves the DENY is the policy, not a fluke).

Writes benchmarks/results/effect_boundary_edges.json with per-case pass/fail tallies.
"""

import json
from pathlib import Path

from jataayu.config.policy import AgentPolicy
from jataayu.guards.effect_boundary import (
    CommitRejected,
    Decision,
    EffectBoundary,
    Provenance,
    Value,
)

HERE = Path(__file__).parent
OUT_DIR = HERE / "results"
OUT_DIR.mkdir(exist_ok=True)


def run_commit_cases():
    """Path A — preview -> commit token binding."""
    cases = []

    # A1: happy path — unmutated commit executes.
    eb = EffectBoundary()
    pv = eb.preview(
        "write_file",
        {"path": "notes.md", "content": "hello"},
        values=[Value("hello", Provenance.TRUSTED, source="operator")],
    )
    ran = {"v": False}

    def _exec():
        ran["v"] = True
        return "ok"

    ok_a1, detail_a1 = False, ""
    try:
        assert pv.decision is Decision.ALLOW, f"expected ALLOW, got {pv.decision.value}"
        out = eb.commit(pv, {"path": "notes.md", "content": "hello"}, _exec)
        ok_a1 = (out == "ok") and ran["v"]
        detail_a1 = "unmutated commit executed"
    except Exception as e:  # noqa: BLE001
        detail_a1 = f"unexpected: {type(e).__name__}: {e}"
    cases.append(
        {"case": "A1_happy_path_commit", "expect": "executes", "passed": ok_a1, "detail": detail_a1}
    )

    # A2: mutated params after authorization -> CommitRejected.
    eb = EffectBoundary()
    pv = eb.preview(
        "write_file",
        {"path": "notes.md", "content": "hello"},
        values=[Value("hello", Provenance.TRUSTED, source="operator")],
    )
    fired = {"v": False}
    ok_a2, detail_a2 = False, ""
    try:
        eb.commit(
            pv, {"path": "/etc/passwd", "content": "pwned"}, lambda: fired.__setitem__("v", True)
        )
        detail_a2 = "NO exception raised — mutation NOT blocked (FAIL)"
    except CommitRejected as e:
        ok_a2 = not fired["v"]
        detail_a2 = f"CommitRejected raised, executor did not fire: {e}"
    except Exception as e:  # noqa: BLE001
        detail_a2 = f"wrong exception type: {type(e).__name__}: {e}"
    cases.append(
        {
            "case": "A2_mutated_params_rejected",
            "expect": "CommitRejected",
            "passed": ok_a2,
            "detail": detail_a2,
        }
    )

    # A3: committing a non-ALLOW preview (untrusted -> NETWORK NEEDS_APPROVAL) -> CommitRejected.
    eb = EffectBoundary()
    pv = eb.preview(
        "send_email",
        {"to": "x@y.com", "body": "hi"},
        values=[Value("hi", Provenance.UNTRUSTED, source="web-page")],
    )
    fired = {"v": False}
    ok_a3, detail_a3 = False, ""
    try:
        assert pv.decision is not Decision.ALLOW, f"expected non-ALLOW, got {pv.decision.value}"
        assert pv.commit_token is None, "no token should be issued for a non-ALLOW preview"
        eb.commit(pv, {"to": "x@y.com", "body": "hi"}, lambda: fired.__setitem__("v", True))
        detail_a3 = "NO exception — unauthorized action committed (FAIL)"
    except CommitRejected as e:
        ok_a3 = not fired["v"]
        detail_a3 = f"CommitRejected raised on {pv.decision.value} preview: {e}"
    except Exception as e:  # noqa: BLE001
        detail_a3 = f"wrong exception type: {type(e).__name__}: {e}"
    cases.append(
        {
            "case": "A3_commit_unauthorized_preview_rejected",
            "expect": "CommitRejected",
            "passed": ok_a3,
            "detail": detail_a3,
        }
    )

    return cases


def run_capability_cases():
    """Path B — capability-policy DENY at _decide step 1."""
    cases = []

    # B1: forbid 'exec'; a TRUSTED shell action must still be DENIED (capability wins).
    pol = AgentPolicy(name="restricted", forbidden_capabilities=["exec"])
    eb = EffectBoundary(policy=pol)
    pv = eb.preview(
        "bash",
        {"command": "pytest -q"},
        values=[Value("pytest -q", Provenance.TRUSTED, source="operator")],
    )
    ok_b1 = pv.decision is Decision.DENY and "exec" in pv.violations
    cases.append(
        {
            "case": "B1_forbidden_capability_deny",
            "expect": "DENY",
            "passed": ok_b1,
            "detail": f"decision={pv.decision.value} violations={pv.violations} reason={pv.reason!r}",
        }
    )

    # B2: allowlist mode (only fs_read allowed); a TRUSTED network action needs network_write
    #     which is not in the allowlist -> DENY.
    pol = AgentPolicy(name="read-only", allowed_capabilities=["fs_read"])
    eb = EffectBoundary(policy=pol)
    pv = eb.preview(
        "send_email",
        {"to": "a@b.com", "body": "hi"},
        values=[Value("hi", Provenance.TRUSTED, source="operator")],
    )
    ok_b2 = pv.decision is Decision.DENY and "network_write" in pv.violations
    cases.append(
        {
            "case": "B2_allowlist_capability_not_listed_deny",
            "expect": "DENY",
            "passed": ok_b2,
            "detail": f"decision={pv.decision.value} violations={pv.violations} reason={pv.reason!r}",
        }
    )

    # B3: control — capability allowed -> ALLOW (proves the DENY above is the policy, not provenance).
    pol = AgentPolicy(name="permitted", allowed_capabilities=["network_write"])
    eb = EffectBoundary(policy=pol)
    pv = eb.preview(
        "send_email",
        {"to": "a@b.com", "body": "hi"},
        values=[Value("hi", Provenance.TRUSTED, source="operator")],
    )
    ok_b3 = pv.decision is Decision.ALLOW and not pv.violations
    cases.append(
        {
            "case": "B3_control_capability_allowed_allow",
            "expect": "ALLOW",
            "passed": ok_b3,
            "detail": f"decision={pv.decision.value} violations={pv.violations} reason={pv.reason!r}",
        }
    )

    return cases


def main():
    commit_cases = run_commit_cases()
    cap_cases = run_capability_cases()
    all_cases = commit_cases + cap_cases

    passed = sum(1 for c in all_cases if c["passed"])
    failed = len(all_cases) - passed

    result = {
        "eval": "effect_boundary_edges",
        "description": "commit() token-binding and capability-policy DENY paths (zero prior coverage)",
        "n_cases": len(all_cases),
        "n_passed": passed,
        "n_failed": failed,
        "all_passed": failed == 0,
        "groups": {
            "commit_token_binding": {
                "n": len(commit_cases),
                "passed": sum(1 for c in commit_cases if c["passed"]),
            },
            "capability_policy_deny": {
                "n": len(cap_cases),
                "passed": sum(1 for c in cap_cases if c["passed"]),
            },
        },
        "cases": all_cases,
    }

    out = OUT_DIR / "effect_boundary_edges.json"
    out.write_text(json.dumps(result, indent=2))

    print(f"[effect-boundary edges] {passed}/{len(all_cases)} cases passed")
    for c in all_cases:
        mark = "PASS" if c["passed"] else "FAIL"
        print(f"  [{mark}] {c['case']:44} expect={c['expect']:>15}  {c['detail']}")
    print(f"\nwrote {out}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
