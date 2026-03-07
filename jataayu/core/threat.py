"""
Jataayu threat model — ThreatResult, ThreatLevel, ThreatType dataclasses.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ThreatLevel(Enum):
    """Severity levels for detected threats."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"

    def __lt__(self, other):
        order = [ThreatLevel.CLEAN, ThreatLevel.LOW, ThreatLevel.MEDIUM,
                 ThreatLevel.HIGH, ThreatLevel.BLOCKED]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        return self == other or self < other

    def __gt__(self, other):
        return not self <= other

    def __ge__(self, other):
        return self == other or self > other


class ThreatType(Enum):
    """Types of threats Jataayu can detect."""
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    SOCIAL_ENGINEERING = "social_engineering"
    UNICODE_BYPASS = "unicode_bypass"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    PII_LEAKAGE = "pii_leakage"
    PRIVACY_VIOLATION = "privacy_violation"


@dataclass
class ThreatResult:
    """
    Result of a Jataayu guard evaluation.

    Attributes:
        threat_level: Overall severity of detected threat.
        threat_types: List of specific threat categories detected.
        risk_score: Float 0.0–1.0 representing overall risk.
        original_text: The text that was evaluated.
        sanitized_text: Cleaned/rewritten text (if applicable).
        explanation: Human-readable explanation of findings.
        surface: The surface context (e.g., "github-issue", "group-chat").
        blocked: Whether the content was fully blocked.
        matched_patterns: List of regex patterns that matched (inbound).
        llm_used: Whether the LLM slow path was invoked.
    """
    threat_level: ThreatLevel
    threat_types: list[ThreatType] = field(default_factory=list)
    risk_score: float = 0.0
    original_text: str = ""
    sanitized_text: Optional[str] = None
    explanation: str = ""
    surface: str = "unknown"
    blocked: bool = False
    matched_patterns: list[str] = field(default_factory=list)
    llm_used: bool = False

    @property
    def is_safe(self) -> bool:
        """True if the content is safe to process/send."""
        return self.threat_level in (ThreatLevel.CLEAN, ThreatLevel.LOW)

    @property
    def output_text(self) -> Optional[str]:
        """Returns sanitized_text if available, otherwise original_text (when safe)."""
        if self.blocked:
            return None
        return self.sanitized_text if self.sanitized_text else self.original_text

    def to_dict(self) -> dict:
        return {
            "threat_level": self.threat_level.value,
            "threat_types": [t.value for t in self.threat_types],
            "risk_score": self.risk_score,
            "is_safe": self.is_safe,
            "blocked": self.blocked,
            "explanation": self.explanation,
            "surface": self.surface,
            "llm_used": self.llm_used,
            "matched_patterns": self.matched_patterns,
        }

    def __repr__(self) -> str:
        types_str = ", ".join(t.value for t in self.threat_types) or "none"
        return (
            f"ThreatResult(level={self.threat_level.value}, "
            f"score={self.risk_score:.2f}, "
            f"types=[{types_str}], "
            f"surface={self.surface!r})"
        )
