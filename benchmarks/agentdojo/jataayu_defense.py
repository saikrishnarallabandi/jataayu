"""
Jataayu as an AgentDojo prompt-injection defense
================================================
Adapter that plugs Jataayu's inbound guard into the AgentDojo benchmark
(ETH SPY Lab, https://github.com/ethz-spylab/agentdojo) as a tool-output
injection detector.

AgentDojo models a defense as a `PromptInjectionDetector` pipeline element that
sits *after* the tool executor and *before* the agent LLM in the tools loop: it
inspects each tool result before the model consumes it and, on a positive
detection, either scrubs the offending text (`transform`) or aborts the agent
(`raise_on_injection=True`). The only method a concrete detector must supply is
`detect(tool_output) -> (is_injection, score)`.

Jataayu's `jataayu_check_inbound(text, surface)` returns a status in
{SAFE, LOW, MEDIUM, HIGH} (HIGH == a real injection/manipulation attempt). This
adapter maps that status onto AgentDojo's boolean+score contract. The detection
itself is deterministic and LLM-free — the guard's fast path — so the *defense*
adds no API cost; only the agent model under test does.

Pinned against agentdojo 0.1.35.
"""
from __future__ import annotations

from jataayu import jataayu_check_inbound, jataayu_sanitize_inbound

try:
    from agentdojo.agent_pipeline import PromptInjectionDetector
    from agentdojo.types import text_content_block_from_string
except ImportError as e:  # pragma: no cover - surfaced only without agentdojo installed
    raise ImportError(
        "agentdojo is required to use this defense adapter. "
        "Install it into the eval venv: pip install 'agentdojo==0.1.35'"
    ) from e


# Jataayu status strings, ordered by severity, mapped to a monotone score so
# AgentDojo's (is_injection, score) contract carries a meaningful confidence.
_STATUS_SCORE = {"SAFE": 0.0, "LOW": 0.0, "MEDIUM": 0.5, "HIGH": 1.0}


class JataayuPIDetector(PromptInjectionDetector):
    """
    Jataayu inbound guard as an AgentDojo PI defense.

    Args:
        min_status: the lowest Jataayu status that counts as an injection.
            "HIGH" (default) is the conservative, low-false-positive setting —
            block only confirmed injections. "MEDIUM" is more aggressive (blocks
            ambiguous cases too), useful for an ablation on the utility/ASR
            trade-off.
        use_llm: whether Jataayu may use its LLM slow path for ambiguous cases.
            Off by default so the defense stays deterministic and free.
        surgical: when True (default), a detected message is scrubbed by excising
            only the injected block (Jataayu's sanitize) rather than discarding
            the whole tool result. AgentDojo plants injections *inside* data the
            agent needs (a calendar description, an email body), so full omission
            — AgentDojo's default transform — starves the task and collapses
            utility under attack. Surgical scrub preserves the benign remainder;
            if the injection can't be cleanly excised it falls back to full
            omission, so detection is never weakened (the removed text is always
            re-verified safe). Set False to reproduce the drop-the-message baseline.
        mode / raise_on_injection: passed through to PromptInjectionDetector.
            mode="message" checks each tool message in isolation; scrub-on-detect
            (raise_on_injection=False) is the AgentDojo default.
    """

    def __init__(
        self,
        *,
        min_status: str = "HIGH",
        use_llm: bool = False,
        surgical: bool = True,
        mode: str = "message",
        raise_on_injection: bool = False,
    ) -> None:
        super().__init__(mode=mode, raise_on_injection=raise_on_injection)
        if min_status not in _STATUS_SCORE:
            raise ValueError(f"min_status must be one of {list(_STATUS_SCORE)}")
        self.min_status = min_status
        self._threshold = _STATUS_SCORE[min_status]
        self.use_llm = use_llm
        self.surgical = surgical
        self.name = f"jataayu_pi_detector({min_status.lower()})"

    def detect(self, tool_output: str) -> tuple[bool, float]:
        result = jataayu_check_inbound(
            tool_output, surface="tool-output", use_llm=self.use_llm
        )
        score = _STATUS_SCORE.get(result["status"], 0.0)
        is_injection = score >= self._threshold and score > 0.0
        return is_injection, score

    def transform(self, tool_output):
        """Surgically excise the injected block from each text block, preserving
        the benign remainder. Falls back to AgentDojo's full-omission marker only
        when Jataayu cannot cleanly remove the injection (sanitize returns "")."""
        if not self.surgical:
            return super().transform(tool_output)
        out = []
        for block in tool_output:
            if block.get("type") != "text":
                out.append(block)
                continue
            cleaned = jataayu_sanitize_inbound(
                block.get("content") or "", surface="tool-output", use_llm=self.use_llm
            )
            out.append(
                text_content_block_from_string(cleaned)
                if cleaned.strip()
                else text_content_block_from_string(
                    "<Data omitted because a prompt injection was detected>"
                )
            )
        return out
