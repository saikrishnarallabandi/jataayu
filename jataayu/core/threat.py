"""
Jataayu threat model — ThreatResult, ThreatLevel, ThreatType, taint tracking.
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
    CREDENTIAL_LEAK = "credential_leak"
    TAINT_FLOW = "taint_flow"


# ---------------------------------------------------------------------------
# Taint tracking — for Clinejection flow analysis (Issue #3)
# ---------------------------------------------------------------------------

class TaintSource(Enum):
    """
    Sources from which tainted content can originate.

    Taint flows from an untrusted source → through the agent → into a sink.
    The Clinejection attack: malicious content in a GitHub issue or web page
    is read by a coding agent (Cline, Claude Code, Cursor), which then executes
    instructions embedded in that content as if they were legitimate tool calls.
    """
    NONE = "none"                       # Content is not tainted
    GITHUB_ISSUE = "github_issue"       # GitHub issue body (classic Clinejection)
    GITHUB_PR = "github_pr"             # PR description or diff
    GITHUB_COMMENT = "github_comment"   # PR/issue comment
    WEB_PAGE = "web_page"               # Fetched web content
    EMAIL = "email"                     # Email body
    USER_INPUT = "user_input"           # Direct user message (elevated)
    EXTERNAL_API = "external_api"       # API response from external service
    FILE_SYSTEM = "file_system"         # File content from disk (untrusted repo)
    UNKNOWN_EXTERNAL = "unknown"        # Unknown external source


class TaintSink(Enum):
    """
    Dangerous sinks where tainted content must not flow without sanitization.

    These represent operations that have significant impact when fed malicious
    content — the Clinejection kill chain ends at one of these sinks.
    """
    NONE = "none"
    SHELL_EXECUTION = "shell_execution"     # bash, sh, exec()
    CODE_EVAL = "code_eval"                 # eval(), exec(), Python/JS eval
    FILE_WRITE = "file_write"               # Writing to filesystem
    NETWORK_REQUEST = "network_request"     # curl, wget, fetch()
    TOOL_CALL = "tool_call"                 # MCP tool call parameters
    AGENT_INSTRUCTION = "agent_instruction" # Fed back as agent instructions
    LLM_PROMPT = "llm_prompt"              # Injected into another LLM call
    SECRET_ACCESS = "secret_access"         # Reading env vars, keychain, etc.


@dataclass
class TaintState:
    """
    Tracks taint from source through propagation to sink.

    When content from an untrusted source (e.g., a GitHub issue) is read by
    the agent and then flows into a dangerous operation (e.g., a shell execution
    tool call), that constitutes a Clinejection-style taint flow.

    Attributes:
        is_tainted: Whether this content is marked as tainted.
        source: Where the taint originated.
        sink: Where the taint is flowing to (if detected).
        propagation_path: Ordered list of surfaces/operations the taint flowed through.
        taint_id: Unique identifier for tracking this taint instance.
    """
    is_tainted: bool = False
    source: TaintSource = TaintSource.NONE
    sink: TaintSink = TaintSink.NONE
    propagation_path: list[str] = field(default_factory=list)
    taint_id: Optional[str] = None

    @property
    def is_dangerous_flow(self) -> bool:
        """True if tainted content is flowing into a dangerous sink."""
        return (
            self.is_tainted
            and self.sink != TaintSink.NONE
            and self.sink != TaintSink.AGENT_INSTRUCTION  # agent instructions are always watched
        )

    def to_dict(self) -> dict:
        return {
            "is_tainted": self.is_tainted,
            "source": self.source.value,
            "sink": self.sink.value,
            "propagation_path": self.propagation_path,
            "taint_id": self.taint_id,
            "is_dangerous_flow": self.is_dangerous_flow,
        }


# ---------------------------------------------------------------------------
# ThreatResult
# ---------------------------------------------------------------------------

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
        taint: Taint tracking state for Clinejection flow analysis.
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
    taint: TaintState = field(default_factory=TaintState)

    @property
    def is_safe(self) -> bool:
        """True if the content is safe to process/send."""
        if self.taint.is_tainted and self.taint.is_dangerous_flow:
            return False
        return self.threat_level in (ThreatLevel.CLEAN, ThreatLevel.LOW)

    @property
    def output_text(self) -> Optional[str]:
        """Returns sanitized_text if available, otherwise original_text (when safe)."""
        if self.blocked:
            return None
        return self.sanitized_text if self.sanitized_text else self.original_text

    def to_dict(self) -> dict:
        d = {
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
        if self.taint.is_tainted:
            d["taint"] = self.taint.to_dict()
        return d

    def __repr__(self) -> str:
        types_str = ", ".join(t.value for t in self.threat_types) or "none"
        taint_str = f", tainted_from={self.taint.source.value}" if self.taint.is_tainted else ""
        return (
            f"ThreatResult(level={self.threat_level.value}, "
            f"score={self.risk_score:.2f}, "
            f"types=[{types_str}], "
            f"surface={self.surface!r}"
            f"{taint_str})"
        )
