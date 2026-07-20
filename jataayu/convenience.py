"""
Jataayu convenience API — DEPRECATED, use `jataayu.api`.

Every name here is a thin wrapper over its `jataayu.api` counterpart and emits a
DeprecationWarning naming the replacement:

    check_inbound     -> jataayu_check_inbound
    check_outbound    -> jataayu_check_outbound
    sanitize_inbound  -> jataayu_sanitize_inbound
    reset_guards      -> jataayu.api.reset_guards

The wrappers keep their historical TUPLE return shape, so existing callers do not
break. That means one status string still differs from the canonical API: for clean
inbound content this returns "LOW" where `jataayu_check_inbound` reports "SAFE".
Changing it here would silently reclassify content for callers that branch on the
string, so the difference is preserved and warned about instead. New code should use
`jataayu.api` and read `result["status"]`.
"""
from __future__ import annotations

import warnings
from typing import Optional

from jataayu import api

# Kept for backwards compatibility: this was always empty — a generic install must
# not redact arbitrary names out of the box.
DEFAULT_PROTECTED_NAMES: list[str] = []


def _warn(old: str, new: str, extra: str = "") -> None:
    warnings.warn(
        f"jataayu.convenience.{old}() is deprecated; use jataayu.{new}(). {extra}".strip(),
        DeprecationWarning,
        stacklevel=3,
    )


def check_inbound(
    content: str,
    surface: str = "unknown",
    use_llm: bool = False,
) -> tuple[str, str]:
    """
    DEPRECATED — use `jataayu_check_inbound`, which returns a dict.

    Returns:
        (status, findings) with status in "LOW" | "MEDIUM" | "HIGH". Note this
        collapses the canonical "SAFE" and "LOW" statuses into "LOW".
    """
    _warn(
        "check_inbound",
        "jataayu_check_inbound",
        'It returns a dict, and reports clean content as "SAFE" where this returns "LOW".',
    )
    result = api.jataayu_check_inbound(content, surface=surface, use_llm=use_llm)
    status = "LOW" if result["status"] in ("SAFE", "LOW") else result["status"]
    return status, result["findings"]


def sanitize_inbound(
    content: str,
    surface: str = "unknown",
    use_llm: bool = False,
) -> str:
    """DEPRECATED — use `jataayu_sanitize_inbound`. Same return value."""
    _warn("sanitize_inbound", "jataayu_sanitize_inbound")
    return api.jataayu_sanitize_inbound(content, surface=surface, use_llm=use_llm)


def check_outbound(
    content: str,
    surface: str = "public",
    protected_names: Optional[list[str]] = None,
    use_llm: bool = False,
) -> tuple[str, str]:
    """
    DEPRECATED — use `jataayu_check_outbound`, which returns a dict.

    Returns:
        (status, output) with status in "SAFE" | "WARN" | "BLOCK". `output` is the
        redacted text when not SAFE, and the unchanged input when SAFE.
    """
    _warn("check_outbound", "jataayu_check_outbound", "It returns a dict.")
    result = api.jataayu_check_outbound(
        content,
        surface=surface,
        protected_names=protected_names,
        use_llm=use_llm,
    )
    if result["status"] == "SAFE":
        return "SAFE", content
    return result["status"], result["redacted"]


def reset_guards() -> None:
    """DEPRECATED — use `jataayu.api.reset_guards`. Resets the shared guard cache."""
    _warn("reset_guards", "api.reset_guards")
    api.reset_guards()
