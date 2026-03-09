"""
Jataayu convenience API
========================
Simple functional interface matching the SOUL.md integration pattern:

    from jataayu.convenience import check_inbound, check_outbound

    status, findings = check_inbound(content, surface="github-issue")
    status, redacted = check_outbound(content, surface="discord-channel")

These wrap InboundGuard and OutboundGuard with sensible defaults.
"""
from __future__ import annotations

from typing import Optional

from jataayu.guards.inbound import InboundGuard
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig
from jataayu.core.threat import ThreatLevel

# Default protected names — family members that should never appear in outbound
# content on shared surfaces. Configure via PrivacyConfig for custom lists.
DEFAULT_PROTECTED_NAMES = [
    "Sai", "Suchi", "Veda", "Tarak",
    "Suresh", "Sirisha", "Venkata",
]

# Singleton guards (lazy-initialized)
_inbound_guard: Optional[InboundGuard] = None
_outbound_guard: Optional[OutboundGuard] = None


def _get_inbound_guard(use_llm: bool = False) -> InboundGuard:
    global _inbound_guard
    if _inbound_guard is None:
        _inbound_guard = InboundGuard(use_llm=use_llm)
    return _inbound_guard


def _get_outbound_guard(
    protected_names: Optional[list[str]] = None,
    use_llm: bool = False,
) -> OutboundGuard:
    global _outbound_guard
    if _outbound_guard is None:
        config = PrivacyConfig(
            protected_names=protected_names or DEFAULT_PROTECTED_NAMES,
            use_llm=use_llm,
        )
        _outbound_guard = OutboundGuard(config)
    return _outbound_guard


def check_inbound(
    content: str,
    surface: str = "unknown",
    use_llm: bool = False,
) -> tuple[str, str]:
    """
    Check inbound content for injection/manipulation threats.

    Args:
        content: External content to evaluate.
        surface: Source surface (github-issue, web-page, email, whatsapp, etc.)
        use_llm: Whether to use LLM slow path for ambiguous cases.

    Returns:
        (status, findings) where:
            status: "LOW" | "MEDIUM" | "HIGH"
            findings: Human-readable explanation of what was found.

    Decision logic:
        LOW    → proceed normally
        MEDIUM → proceed with caution, note warning
        HIGH   → stop, alert user, do not act
    """
    guard = _get_inbound_guard(use_llm=use_llm)
    result = guard.check(content, surface=surface)

    # Map ThreatLevel to simple status strings
    if result.threat_level in (ThreatLevel.CLEAN, ThreatLevel.LOW):
        status = "LOW"
    elif result.threat_level == ThreatLevel.MEDIUM:
        status = "MEDIUM"
    else:  # HIGH or BLOCKED
        status = "HIGH"

    return status, result.explanation


def check_outbound(
    content: str,
    surface: str = "public",
    protected_names: Optional[list[str]] = None,
    use_llm: bool = False,
) -> tuple[str, str]:
    """
    Check outbound content for privacy/PII violations before sending.

    Args:
        content: Draft message to evaluate.
        surface: Target surface (discord-channel, whatsapp-group, github-comment, etc.)
        protected_names: Names that must never appear. Defaults to family names.
        use_llm: Whether to use LLM for sanitization.

    Returns:
        (status, output) where:
            status: "SAFE" | "WARN" | "BLOCK"
            output: Redacted/sanitized version (same as input if SAFE).

    Decision logic:
        SAFE → send as-is
        WARN → review findings, consider edits; output is sanitized version
        BLOCK → do not send; output is redacted version or explanation
    """
    guard = _get_outbound_guard(
        protected_names=protected_names,
        use_llm=use_llm,
    )
    result = guard.check(content, surface=surface)

    # Map ThreatLevel to simple status strings
    if result.is_safe:
        return "SAFE", content
    elif result.blocked:
        # Try to get a sanitized version
        sanitized = guard.sanitize(content, surface=surface)
        return "BLOCK", sanitized
    else:  # MEDIUM or HIGH but not blocked
        sanitized = guard.sanitize(content, surface=surface)
        return "WARN", sanitized


def reset_guards() -> None:
    """Reset singleton guards (useful for testing with different configs)."""
    global _inbound_guard, _outbound_guard
    _inbound_guard = None
    _outbound_guard = None
