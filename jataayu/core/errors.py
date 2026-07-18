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
