"""Jataayu exception types."""

from __future__ import annotations


class SecurityError(Exception):
    """Raised by a caller when Jataayu refuses an action, an input, or an outbound message.

    Jataayu itself returns verdicts rather than raising — a guard that throws cannot tell you
    the risk score of something it let through. This is the exception the integration examples
    raise at the point a verdict is enforced, so callers have one type to catch across the
    inbound, outbound, and effect-boundary surfaces::

        result = jataayu_check_inbound(body, surface="github-issue")
        if result["status"] == "HIGH":
            raise SecurityError(f"Blocked: {result['findings']}")
    """


class UnknownAgentError(ValueError):
    """Raised when an `agent=` name is not defined in the policy file.

    Not a verdict — a caller error, which is why this raises where the guards return.
    Naming an agent asserts it exists; if the name does not resolve, the restrictions
    the caller believes are in force are not, and the failure is invisible from the
    call site. Subclasses ValueError because the policy loader's other
    caller-error paths (dead keys, unsupported `version:`) already raise ValueError.

    Pass ``agent=None`` to run on the policy's ``defaults:`` block deliberately.
    """
