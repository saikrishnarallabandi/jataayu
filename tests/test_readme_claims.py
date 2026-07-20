"""The README's counts, checked against the live catalogs.

Prose claims about how many patterns ship, or which surfaces exist, drift the moment someone
adds one and forgets the docs. Nothing here hardcodes an expected number: every number is read
out of README.md and compared to the code, so the two are forced to agree in both directions.

If a claim's phrasing changes so this file can no longer find it, the test FAILS rather than
silently passing — a doc test that quietly stops matching is worse than no test.
"""
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
