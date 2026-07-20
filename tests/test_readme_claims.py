"""The README's counts, checked against the live catalogs.

Prose claims about how many patterns ship, or which surfaces exist, drift the moment someone
adds one and forgets the docs. Nothing here hardcodes an expected number: every number is read
out of README.md and compared to the code, so the two are forced to agree in both directions.

If a claim's phrasing changes so this file can no longer find it, the test FAILS rather than
silently passing — a doc test that quietly stops matching is worse than no test.
"""
import json
import re
from pathlib import Path

import pytest

from jataayu.guards.inbound import INJECTION_PATTERNS
from jataayu.guards.outbound import (
    _CREDENTIAL_PATTERNS,
    _INTERNAL_CONTEXT_PATTERNS,
    _PII_PATTERNS,
)
from jataayu.surfaces.profiles import SURFACE_PROFILES

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"


def _find(pattern: str, label: str) -> re.Match:
    text = README.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    if match is None:
        pytest.fail(
            f"Could not find the {label} claim in README.md.\n"
            f"  looked for: {pattern}\n"
            f"  Either the README was reworded (restore a phrasing this matches), or this "
            f"check is stale — fix tests/test_readme_claims.py. Do not delete the claim to "
            f"make this pass."
        )
    return match


def _assert(label: str, claimed: str, actual: int, source: str) -> None:
    assert int(claimed) == actual, (
        f"README.md claims {claimed} {label}, but the code has {actual}.\n"
        f"  live count: {source}\n"
        f"  Fix whichever is wrong: README.md, or the pattern catalog itself."
    )


def test_inbound_pattern_count():
    match = _find(r"(\d+) compiled regex patterns over normalized views", "inbound fast-path")
    _assert(
        "inbound compiled regex patterns",
        match.group(1),
        len(INJECTION_PATTERNS),
        "len(jataayu.guards.inbound.INJECTION_PATTERNS)",
    )


def test_fast_path_pattern_breakdown():
    match = _find(
        r"(\d+) regex patterns\D+(\d+) inbound, (\d+) outbound "
        r"\((\d+) PII \+\s*(\d+) credential \+ (\d+) internal-context\)",
        "fast-path pattern breakdown",
    )
    total, inbound, outbound, pii, cred, internal = match.groups()

    counts = {
        "inbound patterns": (inbound, len(INJECTION_PATTERNS), "len(jataayu.guards.inbound.INJECTION_PATTERNS)"),
        "outbound PII patterns": (pii, len(_PII_PATTERNS), "len(jataayu.guards.outbound._PII_PATTERNS)"),
        "outbound credential patterns": (
            cred, len(_CREDENTIAL_PATTERNS), "len(jataayu.guards.outbound._CREDENTIAL_PATTERNS)"),
        "outbound internal-context patterns": (
            internal, len(_INTERNAL_CONTEXT_PATTERNS),
            "len(jataayu.guards.outbound._INTERNAL_CONTEXT_PATTERNS)"),
    }
    for label, (claimed, actual, source) in counts.items():
        _assert(label, claimed, actual, source)

    live_outbound = len(_PII_PATTERNS) + len(_CREDENTIAL_PATTERNS) + len(_INTERNAL_CONTEXT_PATTERNS)
    _assert("outbound patterns in total", outbound, live_outbound, "jataayu.guards.outbound: _PII_PATTERNS + _CREDENTIAL_PATTERNS + _INTERNAL_CONTEXT_PATTERNS")
    _assert(
        "regex patterns in total",
        total,
        len(INJECTION_PATTERNS) + live_outbound,
        "inbound + outbound",
    )


def test_outbound_pattern_count_in_latency_note():
    """The latency section repeats the outbound count in prose ("runs 45 patterns")."""
    match = _find(r"it runs (\d+) patterns over long", "outbound-latency")
    _assert(
        "outbound patterns",
        match.group(1),
        len(_PII_PATTERNS) + len(_CREDENTIAL_PATTERNS) + len(_INTERNAL_CONTEXT_PATTERNS),
        "PII + credential + internal in jataayu.guards.outbound",
    )


_SURFACE_ROW = re.compile(
    r"^\|((?:\s*`[\w./-]+`\s*/?)+)\|\s*\S+\s*(low|medium|high)\s*"
    r"\|\s*(✅|❌)\s*\|\s*(✅|❌)\s*\|\s*([\d.]+)\s*\|",
    re.M,
)


def test_surface_profile_table():
    rows = _SURFACE_ROW.findall(README.read_text(encoding="utf-8"))
    if not rows:
        pytest.fail(
            "Could not parse any row of the Surface Profiles table in README.md. Expected rows "
            "like: | `github-issue` | 🔴 low | ✅ | ❌ | 1.2 | ... |\n"
            "  Restore that shape, or fix tests/test_readme_claims.py."
        )

    documented = {}
    for names, trust, inbound, outbound, mult in rows:
        for name in re.findall(r"`([^`]+)`", names):
            documented[name] = (trust, inbound == "✅", outbound == "✅", float(mult))

    missing = sorted(set(SURFACE_PROFILES) - set(documented))
    extra = sorted(set(documented) - set(SURFACE_PROFILES))
    assert not missing and not extra, (
        f"The README's Surface Profiles table does not match SURFACE_PROFILES.\n"
        f"  in code but undocumented: {missing or 'none'}\n"
        f"  documented but not in code: {extra or 'none'}\n"
        f"  Fix README.md's table, or jataayu/surfaces/profiles.py."
    )

    for name, (trust, inbound, outbound, mult) in documented.items():
        live = SURFACE_PROFILES[name]
        claimed = (trust, inbound, outbound, mult)
        actual = (
            live["trust_level"],
            live["inbound_strict"],
            live["outbound_strict"],
            float(live["risk_multiplier"]),
        )
        assert claimed == actual, (
            f"README.md's row for `{name}` claims "
            f"(trust, inbound_strict, outbound_strict, xrisk) = {claimed}, "
            f"but jataayu/surfaces/profiles.py has {actual}.\n"
            f"  Fix whichever is wrong."
        )


# The detector metrics below are transcribed by hand out of frozen result JSON. That is a
# different risk from the counts above -- the JSON does not drift, but a typo in the README does
# not announce itself, and these are the numbers a reader compares against published work.
RESULTS = REPO / "training" / "injection_adapter" / "eval" / "results"


def _result(name: str) -> dict:
    path = RESULTS / name
    assert path.is_file(), (
        f"{path} is missing, but README.md publishes numbers from it. Commit the result file; "
        f"do not delete the claim."
    )
    return json.loads(path.read_text(encoding="utf-8"))


def test_notinject_default_threshold_claim():
    match = _find(r"\*\*Jataayu v0\.1, default τ=0\.5\*\* \| \*\*([\d.]+)\*\*", "NotInject default-τ")
    run = _result("cfp_notinject.ckpt300.json")
    assert run["tau"] == 0.5, f"cfp_notinject.ckpt300.json was scored at τ={run['tau']}, not the default 0.5"
    actual = round(run["notinject"]["od_acc"] * 100, 2)
    assert float(match.group(1)) == actual, (
        f"README.md publishes NotInject over-defense {match.group(1)}% at the default threshold, "
        f"but cfp_notinject.ckpt300.json:notinject.od_acc is {actual}%."
    )


_AUTHORITY_ROW = re.compile(
    r"^\|\s*\*{0,2}([^|*]+?)\*{0,2}\s*\|\s*\*{0,2}(−[\d.]+|\+[\d.]+)\*{0,2}\s*\|"
    r"\s*\*{0,2}(\d+) / 20\*{0,2}\s*\|",
    re.M,
)

# README row label -> result file holding that arm of the ablation. Only the two arms that ran on
# the same machine, dtype and code revision belong here. The Prompt Guard 2 rows were withdrawn:
# they were scored through a different runner in a different environment, so a mean-Δ contrast
# against them measured the environment, not the models. Re-adding a row here means the controlled
# re-run (one box, one adapter dir, one code revision, dtype varied alone) was actually done.
_AUTHORITY_FILES = {
    "Jataayu v0.1": "adversarial_slice.v0.1.json",
    "Qwen3.5-0.8B base, no adapter": "adversarial_slice.v0.1-BASE.json",
}


def test_authority_ablation_table():
    rows = {label: (delta, defeated) for label, delta, defeated in _AUTHORITY_ROW.findall(
        README.read_text(encoding="utf-8")
    )}
    missing = sorted(set(_AUTHORITY_FILES) - set(rows))
    if missing:
        pytest.fail(
            f"Could not parse these rows of the authority-framing table in README.md: {missing}.\n"
            "  Expected rows like: | Jataayu v0.1 | −0.668 | 14 / 20 | ... |\n"
            "  Restore that shape, or fix tests/test_readme_claims.py."
        )

    readded = sorted(label for label in rows if "Prompt Guard" in label)
    assert not readded, (
        f"README.md's authority-framing table has Prompt Guard 2 rows again: {readded}.\n"
        "  That cross-model magnitude was withdrawn -- our arm and Prompt Guard 2's were scored\n"
        "  through different runners in different environments, so the contrast is not like-for-\n"
        "  like. Only re-add it off a controlled re-run, and update _AUTHORITY_FILES with it."
    )

    for label, filename in _AUTHORITY_FILES.items():
        claimed_delta, claimed_defeated = rows[label]
        effect = _result(filename)["ablations"]["authority_prefix"]["authority_effect"]
        # The README uses U+2212 MINUS SIGN, not ASCII hyphen.
        actual_delta = round(effect["mean_delta"], 3)
        assert float(claimed_delta.replace("−", "-").lstrip("+")) == actual_delta, (
            f"README.md's authority row for {label} claims mean Δ {claimed_delta}, but "
            f"{filename}:ablations.authority_prefix.authority_effect.mean_delta is {actual_delta}."
        )
        assert int(claimed_defeated) == effect["n_defeated"], (
            f"README.md's authority row for {label} claims {claimed_defeated}/20 pairs defeated, "
            f"but {filename} records n_defeated={effect['n_defeated']}."
        )
        assert effect["n_pairs"] == 20, (
            f"{filename} has {effect['n_pairs']} authority pairs, but README.md says 20."
        )


def test_uncontrolled_second_run_figures():
    """The second run is quoted in prose to show the disagreement, so it needs the same guard."""
    effect = _result("adversarial_slice.ckpt300.json")["ablations"]["authority_prefix"][
        "authority_effect"
    ]
    match = _find(
        r"reports mean Δ (−[\d.]+) and (\d+) of 20 defeated", "ckpt300 disagreement figures"
    )
    actual = round(effect["mean_delta"], 3)
    assert float(match.group(1).replace("−", "-")) == actual, (
        f"README.md quotes the second run at mean Δ {match.group(1)}, but "
        f"adversarial_slice.ckpt300.json records {actual}."
    )
    assert int(match.group(2)) == effect["n_defeated"], (
        f"README.md quotes the second run at {match.group(2)} of 20 defeated, but "
        f"adversarial_slice.ckpt300.json records {effect['n_defeated']}."
    )


def test_self_referential_counts_disagree_as_published():
    """README says 18/40 in one run and 1/40 in the other. Both halves are checked."""
    claimed = {
        "adversarial_slice.ckpt300.json": int(
            _find(r"\"(\d+) of 40 held-out rows score", "self-ref ckpt300 count").group(1)
        ),
        "adversarial_slice.v0.1.json": int(
            _find(r"puts (\d+) of 40 rows in\s*\n?\s*that band", "self-ref release count").group(1)
        ),
    }
    for filename, n_claimed in claimed.items():
        scores = _result(filename)["per_class"]["self_ref_benign"]["scores"]
        actual = sum(1 for v in scores.values() if v >= 0.9999)
        assert len(scores) == 40, f"{filename} has {len(scores)} self_ref_benign rows, not 40."
        assert n_claimed == actual, (
            f"README.md claims {n_claimed} of 40 self-referential rows score >= 0.9999 in "
            f"{filename}, but the file has {actual}."
        )
