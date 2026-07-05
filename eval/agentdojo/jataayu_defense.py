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

Jataayu's `check_inbound(text, surface)` returns a status in {LOW, MEDIUM, HIGH}
(HIGH == a real injection/manipulation attempt). This adapter maps that status
onto AgentDojo's boolean+score contract. The detection itself is deterministic
and LLM-free — the guard's fast path — so the *defense* adds no API cost; only
the agent model under test does.

Pinned against agentdojo 0.1.35.
"""
from __future__ import annotations

from jataayu.convenience import check_inbound

try:
    from agentdojo.agent_pipeline import PromptInjectionDetector
except ImportError as e:  # pragma: no cover - surfaced only without agentdojo installed
    raise ImportError(
        "agentdojo is required to use this defense adapter. "
        "Install it into the eval venv: pip install 'agentdojo==0.1.35'"
    ) from e


# Jataayu status strings, ordered by severity, mapped to a monotone score so
# AgentDojo's (is_injection, score) contract carries a meaningful confidence.
_STATUS_SCORE = {"LOW": 0.0, "MEDIUM": 0.5, "HIGH": 1.0}


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
        mode / raise_on_injection: passed through to PromptInjectionDetector.
            mode="message" checks each tool message in isolation; scrub-on-detect
            (raise_on_injection=False) is the AgentDojo default.
    """

    def __init__(
        self,
        *,
        min_status: str = "HIGH",
        use_llm: bool = False,
        mode: str = "message",
        raise_on_injection: bool = False,
    ) -> None:
        super().__init__(mode=mode, raise_on_injection=raise_on_injection)
        if min_status not in _STATUS_SCORE:
            raise ValueError(f"min_status must be one of {list(_STATUS_SCORE)}")
        self.min_status = min_status
        self._threshold = _STATUS_SCORE[min_status]
        self.use_llm = use_llm
        self.name = f"jataayu_pi_detector({min_status.lower()})"

    def detect(self, tool_output: str) -> tuple[bool, float]:
        status, _explanation = check_inbound(
            tool_output, surface="tool-output", use_llm=self.use_llm
        )
        score = _STATUS_SCORE.get(status, 0.0)
        is_injection = score >= self._threshold and score > 0.0
        return is_injection, score
