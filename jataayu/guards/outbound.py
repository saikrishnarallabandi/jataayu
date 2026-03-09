"""
Jataayu OutboundGuard
=====================
Protects against privacy, PII, and credential leakage in AI agent outputs
before they reach shared or public surfaces.

This guard covers two leak categories:
  1. **Privacy/PII leakage** — personal info (health, addresses, children's data)
  2. **Credential leakage** — API keys, private keys, DB connection strings,
     bearer tokens, high-entropy secrets (Aguara CRED_001-017)

Architecture:
  Fast path  → regex + protected-name scanning + credential patterns (microseconds)
  Slow path  → LLM rewrite/redaction for nuanced privacy violations

Unlike the InboundGuard (which catches what's coming IN), the OutboundGuard
watches what's going OUT — the missing piece in most AI security frameworks.

The threat: your AI agent may inadvertently include personal names, health info,
financial details, home addresses, or API keys when responding in public channels.
Jataayu catches this before it reaches the audience.

Example:
    config = PrivacyConfig(protected_names=["Alice", "Bob"])
    guard = OutboundGuard(config)
    result = guard.check(draft_reply, surface="group-chat")
    if result.blocked:
        raise ValueError("Draft blocked — contains sensitive info")
    safe_text = result.output_text  # may be sanitized
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional

from jataayu.core.engine import JataayuEngine, LLMBackend
from jataayu.core.threat import ThreatLevel, ThreatResult, ThreatType


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class PrivacyConfig:
    """
    Configuration for the outbound privacy guard.

    Attributes:
        protected_names: Specific names/terms that must never appear in output.
            Typical use: names of minors, family members, protected individuals.
        check_categories: Privacy categories to scan for. All are checked by default.
        llm_url: OpenAI-compatible API base URL for LLM-backed sanitization.
            Leave None to use the configured JataayuEngine LLM backend.
        llm_token: API token for the LLM endpoint.
        llm_model: Model name to use (default: gpt-4o-mini).
        use_llm: Whether to invoke the LLM slow path. Default True.
        llm_threshold: Risk score above which to invoke LLM rewrite. Default 0.3.
        block_threshold: Risk score above which to block entirely. Default 0.9.
    """
    # Names/terms that should never appear in output
    protected_names: list[str] = field(default_factory=list)

    # Categories to always check for
    check_categories: list[str] = field(default_factory=lambda: [
        "minors_info",
        "health",
        "financial",
        "home_address",
        "relationships",
    ])

    # Whether to check for credential leaks (API keys, private keys, etc.)
    check_credentials: bool = True

    # Disabled credential rule IDs (e.g., ["CRED_004"] to silence generic patterns)
    disabled_cred_rules: list[str] = field(default_factory=list)

    # Whether to run high-entropy string detection (may have false positives)
    check_high_entropy: bool = False

    # LLM backend (OpenAI-compatible API URL)
    llm_url: Optional[str] = None
    llm_token: Optional[str] = None
    llm_model: str = "gpt-4o-mini"

    # Behaviour tuning
    use_llm: bool = True
    llm_threshold: float = 0.3
    block_threshold: float = 0.9


# ---------------------------------------------------------------------------
# Pattern library — fast-path PII detection
# ---------------------------------------------------------------------------

# Format: (pattern, ThreatType, base_risk_score, description, categories)
_PII_PATTERNS: list[tuple[str, ThreatType, float, str, list[str]]] = [
    # Home address
    (
        r"\b\d{1,5}\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Blvd|Way|Court|Ct|Place|Pl)\b",
        ThreatType.PRIVACY_VIOLATION, 0.85,
        "Home street address pattern",
        ["home_address"],
    ),
    (
        r"\b(apartment|apt|unit|suite|ste)\.?\s+\d+\b",
        ThreatType.PRIVACY_VIOLATION, 0.70,
        "Apartment/unit number",
        ["home_address"],
    ),
    (
        r"\b\d{5}(-\d{4})?\b",  # US ZIP
        ThreatType.PII_LEAKAGE, 0.35,
        "US ZIP code (possible address component)",
        ["home_address"],
    ),

    # Financial details
    (
        r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        ThreatType.PRIVACY_VIOLATION, 0.95,
        "Credit/debit card number pattern",
        ["financial"],
    ),
    (
        r"\b(ssn|social\s+security(\s+number)?)\s*[:=]?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        ThreatType.PRIVACY_VIOLATION, 0.98,
        "Social Security Number",
        ["financial"],
    ),
    (
        r"\b(salary|income|net\s+worth|annual\s+pay|earns?|makes?)\s+\$[\d,]+",
        ThreatType.PRIVACY_VIOLATION, 0.75,
        "Salary / personal income disclosure",
        ["financial"],
    ),
    (
        r"\b(bank\s+account|routing\s+number|account\s+number)\s*[:=]?\s*[\d\-]+",
        ThreatType.PRIVACY_VIOLATION, 0.90,
        "Bank account details",
        ["financial"],
    ),
    (
        r"\$([\d,]+)\s*(debt|loan|mortgage|owe|owed|balance)",
        ThreatType.PRIVACY_VIOLATION, 0.70,
        "Personal debt/financial liability",
        ["financial"],
    ),

    # Health information
    (
        r"\b(diagnosed|diagnosis|condition|disorder|syndrome|disease|illness|suffers?\s+from|treatment|prescription|medication|therapy|therapist|counseling)\b",
        ThreatType.PRIVACY_VIOLATION, 0.65,
        "Health/medical information",
        ["health"],
    ),
    (
        r"\b(hospital|clinic|doctor|physician|specialist|psychiatrist|psychologist)\s+.{0,30}(visit|appointment|referred|admitted)\b",
        ThreatType.PRIVACY_VIOLATION, 0.72,
        "Medical appointment / visit disclosure",
        ["health"],
    ),

    # Minors' information
    (
        r"\b(my\s+)?(son|daughter|child|kid|baby|toddler|infant)\s+.{0,100}(school|grade|class|teacher|daycare|kindergarten|elementary|preschool|kindergarten)\b",
        ThreatType.PRIVACY_VIOLATION, 0.80,
        "Child's school/education information",
        ["minors_info"],
    ),
    (
        r"\b(my\s+)?(son|daughter|child|kid)\s+(is\s+)?\d+\s+(years?\s+old|months?\s+old)\b",
        ThreatType.PRIVACY_VIOLATION, 0.75,
        "Child's age disclosure",
        ["minors_info"],
    ),
    (
        r"\b(my\s+)?(son|daughter|child|kid)\s+.{0,30}(medical|health|therapy|diagnosis|sick|hospital)\b",
        ThreatType.PRIVACY_VIOLATION, 0.85,
        "Child's health information",
        ["minors_info"],
    ),

    # Relationship details
    (
        r"\b(my\s+)?(wife|husband|spouse|partner|girlfriend|boyfriend)\s+.{0,50}(problem|issue|fight|argument|divorce|separated|cheating)\b",
        ThreatType.PRIVACY_VIOLATION, 0.80,
        "Sensitive relationship information",
        ["relationships"],
    ),
    (
        r"\b(my\s+)?(mother|father|mom|dad|parent|sibling|sister|brother)\s+.{0,50}(health|sick|hospital|diagnosed|passed|died|death)\b",
        ThreatType.PRIVACY_VIOLATION, 0.82,
        "Family member's health/death information",
        ["relationships"],
    ),

    # Phone numbers
    (
        r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        ThreatType.PII_LEAKAGE, 0.60,
        "Phone number",
        ["relationships", "home_address"],
    ),

    # Email addresses (moderate risk — context-dependent)
    (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        ThreatType.PII_LEAKAGE, 0.45,
        "Email address",
        ["relationships"],
    ),
]

# Compile patterns with category tags
_COMPILED_PII: list[tuple[re.Pattern, ThreatType, float, str, list[str]]] = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), threat_type, score, desc, cats)
    for pat, threat_type, score, desc, cats in _PII_PATTERNS
]


# ---------------------------------------------------------------------------
# Credential leak patterns — Aguara CRED_001-017 ported to Python regex
# Format: (pattern, ThreatType, base_risk_score, description, rule_id)
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS: list[tuple[str, ThreatType, float, str, str]] = [
    # CRED_001: OpenAI API key
    (
        r"\bsk-[A-Za-z0-9]{20,}\b",
        ThreatType.CREDENTIAL_LEAK, 0.98,
        "OpenAI API key (sk-...)",
        "CRED_001",
    ),
    # CRED_013: Anthropic API key
    (
        r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
        ThreatType.CREDENTIAL_LEAK, 0.98,
        "Anthropic API key (sk-ant-...)",
        "CRED_013",
    ),
    # CRED_002: AWS access key
    (
        r"\bAKIA[0-9A-Z]{16}\b",
        ThreatType.CREDENTIAL_LEAK, 0.98,
        "AWS access key ID (AKIA...)",
        "CRED_002",
    ),
    # AWS secret access key pattern
    (
        r"\b[A-Za-z0-9/+]{40}\b(?=.*aws|.*secret)",
        ThreatType.CREDENTIAL_LEAK, 0.85,
        "Possible AWS secret access key (40-char base64 near 'aws'/'secret')",
        "CRED_002b",
    ),
    # CRED_003: GitHub personal access token (classic ghp_ and fine-grained github_pat_)
    (
        r"\b(ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b",
        ThreatType.CREDENTIAL_LEAK, 0.98,
        "GitHub personal access token (ghp_/gho_/ghs_/github_pat_...)",
        "CRED_003",
    ),
    # CRED_009: GCP service account key (JSON format)
    (
        r'"private_key"\s*:\s*"-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        ThreatType.CREDENTIAL_LEAK, 0.99,
        "GCP service account private key in JSON",
        "CRED_009",
    ),
    (
        r'"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"',
        ThreatType.CREDENTIAL_LEAK, 0.90,
        "GCP service account email in JSON",
        "CRED_009b",
    ),
    # CRED_005: Private key blocks (RSA, EC, OpenSSH, PKCS8)
    (
        r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PRIVATE|ENCRYPTED)\s+PRIVATE KEY-----",
        ThreatType.CREDENTIAL_LEAK, 0.99,
        "Private key block (RSA/EC/DSA/OpenSSH)",
        "CRED_005",
    ),
    # CRED_006: Database connection strings
    (
        r"\b(postgresql|postgres|mysql|mongodb|redis|mongodb\+srv|mssql|jdbc:(postgresql|mysql|sqlserver))"
        r"://[A-Za-z0-9._\-]+:[^@\s]{3,}@[A-Za-z0-9._\-]+",
        ThreatType.CREDENTIAL_LEAK, 0.97,
        "Database connection string with embedded credentials",
        "CRED_006",
    ),
    # CRED_007: Hardcoded passwords in common patterns
    (
        r"(password|passwd|pwd|pass)\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-=]{8,}['\"]?",
        ThreatType.CREDENTIAL_LEAK, 0.82,
        "Hardcoded password pattern",
        "CRED_007",
    ),
    # CRED_008: Slack and Discord webhooks
    (
        r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+",
        ThreatType.CREDENTIAL_LEAK, 0.95,
        "Slack webhook URL",
        "CRED_008a",
    ),
    (
        r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        ThreatType.CREDENTIAL_LEAK, 0.95,
        "Discord webhook URL",
        "CRED_008b",
    ),
    # CRED_010: JWT tokens (three base64 segments separated by dots)
    (
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        ThreatType.CREDENTIAL_LEAK, 0.88,
        "JWT token (eyJ... format)",
        "CRED_010",
    ),
    # CRED_011: Credential in shell export
    (
        r"export\s+(AWS_SECRET|AWS_ACCESS|API_KEY|SECRET_KEY|TOKEN|PASSWORD|PASSWD"
        r"|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN)\w*\s*=\s*\S+",
        ThreatType.CREDENTIAL_LEAK, 0.90,
        "Credential in shell export statement",
        "CRED_011",
    ),
    # CRED_012: Stripe API key
    (
        r"\b(sk|pk)_(test|live)_[A-Za-z0-9]{20,}\b",
        ThreatType.CREDENTIAL_LEAK, 0.98,
        "Stripe API key (sk_test_/pk_live_/...)",
        "CRED_012",
    ),
    # CRED_014: SendGrid and Twilio API keys
    (
        r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b",
        ThreatType.CREDENTIAL_LEAK, 0.97,
        "SendGrid API key (SG.xxx.xxx)",
        "CRED_014a",
    ),
    (
        r"\bAC[0-9a-f]{32}\b",
        ThreatType.CREDENTIAL_LEAK, 0.88,
        "Twilio Account SID (ACxxx...)",
        "CRED_014b",
    ),
    # CRED_004: Generic API key patterns
    (
        r"(api[_\-]?key|apikey|api[_\-]?token|auth[_\-]?token|access[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}['\"]?",
        ThreatType.CREDENTIAL_LEAK, 0.80,
        "Generic API key or token assignment",
        "CRED_004",
    ),
    # CRED_016: SSH private key in command
    (
        r"(ssh|scp|sftp)\s+.{0,100}-i\s+~?/[^\s]{5,}(id_rsa|id_ed25519|\.pem|\.key)",
        ThreatType.CREDENTIAL_LEAK, 0.82,
        "SSH private key path in command",
        "CRED_016",
    ),
    # Bearer token in HTTP header
    (
        r"(Authorization|Bearer)\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}",
        ThreatType.CREDENTIAL_LEAK, 0.88,
        "Bearer token in Authorization header",
        "CRED_bearer",
    ),
    # HMAC secrets
    (
        r"(hmac[_\-]?(secret|key)|secret[_\-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{20,}['\"]?",
        ThreatType.CREDENTIAL_LEAK, 0.85,
        "HMAC secret or signing key",
        "CRED_hmac",
    ),
]

# Compile credential patterns
_COMPILED_CRED: list[tuple[re.Pattern, ThreatType, float, str, str]] = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), threat_type, score, desc, rule_id)
    for pat, threat_type, score, desc, rule_id in _CREDENTIAL_PATTERNS
]

# Minimum entropy threshold for generic high-entropy string detection
_HIGH_ENTROPY_MIN = 4.5
_HIGH_ENTROPY_MIN_LENGTH = 40


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
    )

# Surface-specific outbound risk multipliers
OUTBOUND_SURFACE_MULTIPLIERS: dict[str, float] = {
    "public": 1.3,
    "github-issue": 1.2,
    "github-comment": 1.2,
    "discord-channel": 1.2,
    "discord-group": 1.2,
    "telegram-group": 1.2,
    "whatsapp": 1.2,
    "group-chat": 1.2,
    "email": 1.1,
    "web-page": 1.0,
    "direct-message": 0.6,
    "internal": 0.3,
    "unknown": 1.0,
}

# Outbound LLM system prompt
_LLM_SYSTEM_PROMPT = """You are Jataayu's outbound privacy guard. Your job is to protect personal privacy before AI-generated text reaches a shared or public surface.

SENSITIVE INFORMATION TO REDACT includes:
- Names and identifying details of minors (children)
- Health, medical, or mental health information
- Financial details (salary, debt, account numbers, card numbers)
- Home addresses, specific locations, or daily routines
- Sensitive relationship details (family conflicts, divorce, etc.)
- Any protected names listed in the context

What is NOT sensitive (fine to include):
- Technical content (code, APIs, market data, system details)
- Public information about public figures
- General geographic regions (city/state level is fine)
- Professional roles/titles without personal details

You will receive:
1. A surface type (e.g., "group-chat", "github-issue")
2. Protected names to always redact
3. The text to review

OUTPUT RULES:
1. If NO sensitive info → output the text EXACTLY as-is (no changes, no commentary)
2. If sensitive info present → rewrite with that info removed/generalized. Be surgical.
3. If the ENTIRE message is sensitive with no technical content → output exactly: BLOCKED
4. Never add explanation, preamble, or commentary. Output ONLY the cleaned text or BLOCKED.
"""


class OutboundGuard(JataayuEngine):
    """
    Guards against privacy/PII leakage in AI agent outbound messages.

    Fast path: regex PII detection + protected-name scanning
    Slow path: LLM-backed rewrite/redaction

    Example:
        config = PrivacyConfig(
            protected_names=["Alice", "Bob"],
            check_categories=["minors_info", "financial"],
        )
        guard = OutboundGuard(config)

        # Check-only mode
        result = guard.check(draft_message, surface="group-chat")
        if not result.is_safe:
            print(f"Privacy risk: {result.explanation}")

        # Check + sanitize
        safe_text = guard.sanitize(draft_message, surface="discord-channel")
    """

    def __init__(
        self,
        config: Optional[PrivacyConfig] = None,
        llm_backend: Optional[LLMBackend] = None,
    ):
        cfg = config or PrivacyConfig()
        super().__init__(
            llm_backend=llm_backend,
            use_llm=cfg.use_llm,
            llm_threshold=cfg.llm_threshold,
        )
        self.config = cfg
        self._compiled_names = self._compile_protected_names(cfg.protected_names)

    def _compile_protected_names(self, names: list[str]) -> list[re.Pattern]:
        """Compile protected names into word-boundary patterns."""
        return [
            re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
            for name in names
            if name.strip()
        ]

    def check(self, text: str, surface: str = "public") -> ThreatResult:
        """
        Evaluate outbound text for privacy/PII violations.

        Args:
            text: Outbound text to evaluate (agent reply, comment, message, etc.)
            surface: Target surface affects how strict the check is.

        Returns:
            ThreatResult. If is_safe is False, consider calling sanitize().
        """
        if not text or not text.strip():
            return ThreatResult(
                threat_level=ThreatLevel.CLEAN,
                original_text=text,
                surface=surface,
                explanation="Empty input",
            )

        fast_result = self._fast_path(text, surface)

        if fast_result.risk_score >= 0.9:
            return fast_result

        if self.use_llm and fast_result.risk_score >= self.llm_threshold:
            return self._slow_path_check(text, surface, fast_result)

        return fast_result

    def sanitize(self, text: str, surface: str = "public") -> str:
        """
        Sanitize outbound text, removing or redacting privacy violations.

        Args:
            text: Text to sanitize.
            surface: Target surface.

        Returns:
            Sanitized text string. Returns "[BLOCKED]" if content was fully blocked.

        Raises:
            RuntimeError: If LLM is unavailable and manual redaction fails.
        """
        result = self.check(text, surface)

        if result.is_safe:
            return text

        if result.blocked and not self.use_llm:
            # In no-LLM mode, attempt regex redaction before fully blocking
            redacted = self._regex_redact(text, result)
            if redacted != text:
                return redacted
            return "[BLOCKED — content contained only sensitive private information]"

        if result.blocked:
            return "[BLOCKED — content contained only sensitive private information]"

        # Need sanitization — try LLM first
        if self.use_llm:
            sanitized = self._llm_sanitize(text, surface)
            if sanitized and sanitized != "[LLM_UNAVAILABLE]":
                if sanitized == "BLOCKED":
                    return "[BLOCKED — content contained only sensitive private information]"
                return sanitized

        # Fallback: regex-based redaction
        return self._regex_redact(text, result)

    def _fast_path(self, text: str, surface: str) -> ThreatResult:
        """Pattern-based privacy and credential scan."""
        matched = []
        threat_types: set[ThreatType] = set()
        max_score = 0.0
        multiplier = OUTBOUND_SURFACE_MULTIPLIERS.get(surface, 1.0)
        active_cats = set(self.config.check_categories)

        # Check PII patterns
        for pattern, threat_type, base_score, desc, cats in _COMPILED_PII:
            if not active_cats.intersection(cats):
                continue
            if pattern.search(text):
                effective_score = min(base_score * multiplier, 1.0)
                matched.append(desc)
                threat_types.add(threat_type)
                max_score = max(max_score, effective_score)

        # Check protected names (score capped at HIGH, not BLOCKED — these can be sanitized)
        for name_pattern in self._compiled_names:
            if name_pattern.search(text):
                matched.append(f"Protected name found: {name_pattern.pattern}")
                threat_types.add(ThreatType.PRIVACY_VIOLATION)
                max_score = max(max_score, min(0.72 * multiplier, 0.89))

        # Check credential patterns (CRED_001-017)
        if self.config.check_credentials:
            cred_matched, cred_types, cred_score = self._check_credentials(
                text, multiplier
            )
            matched.extend(cred_matched)
            threat_types.update(cred_types)
            max_score = max(max_score, cred_score)

        threat_level = self._score_to_level(max_score)

        explanation = ""
        if matched:
            explanation = f"Privacy risk in {len(matched)} area(s): {'; '.join(matched[:3])}"
            if len(matched) > 3:
                explanation += f" (+ {len(matched) - 3} more)"

        return ThreatResult(
            threat_level=threat_level,
            threat_types=list(threat_types),
            risk_score=round(max_score, 3),
            original_text=text,
            surface=surface,
            blocked=threat_level == ThreatLevel.BLOCKED,
            matched_patterns=matched,
            explanation=explanation or "No privacy violations detected",
        )

    def _check_credentials(
        self,
        text: str,
        multiplier: float = 1.0,
    ) -> tuple[list[str], set[ThreatType], float]:
        """
        Scan for credential leaks (Aguara CRED_001-017).
        Returns (matched_descriptions, threat_types, max_score).
        """
        matched: list[str] = []
        threat_types: set[ThreatType] = set()
        max_score = 0.0
        disabled = set(self.config.disabled_cred_rules)

        for pattern, threat_type, base_score, desc, rule_id in _COMPILED_CRED:
            if rule_id in disabled:
                continue
            if pattern.search(text):
                # Credential leaks are critical — don't reduce by multiplier for high-value patterns
                effective_score = min(base_score * max(multiplier, 1.0), 1.0)
                matched.append(f"[{rule_id}] {desc}")
                threat_types.add(threat_type)
                max_score = max(max_score, effective_score)

        # Optional: high-entropy string detection (for generic secrets)
        if self.config.check_high_entropy:
            entropy_findings = self._check_high_entropy(text)
            matched.extend(entropy_findings)
            if entropy_findings:
                threat_types.add(ThreatType.CREDENTIAL_LEAK)
                max_score = max(max_score, 0.72)

        return matched, threat_types, max_score

    @staticmethod
    def _check_high_entropy(text: str) -> list[str]:
        """
        Detect high-entropy strings that may be secrets/tokens.
        Uses Shannon entropy on tokens that look like they could be secrets.
        """
        findings: list[str] = []
        # Look for strings that are long, alphanumeric, and high entropy
        candidates = re.findall(r"[A-Za-z0-9+/=_\-]{" + str(_HIGH_ENTROPY_MIN_LENGTH) + r",}", text)
        for candidate in candidates:
            entropy = _shannon_entropy(candidate)
            if entropy >= _HIGH_ENTROPY_MIN:
                findings.append(
                    f"High-entropy string (len={len(candidate)}, entropy={entropy:.2f}) — possible secret"
                )
        return findings

    def _slow_path_check(self, text: str, surface: str, fast_result: ThreatResult) -> ThreatResult:
        """LLM-backed privacy evaluation (check only, no rewrite)."""
        import json as _json

        check_prompt = _LLM_SYSTEM_PROMPT + "\n\nFor CHECK mode: respond with JSON only:\n{\"threat_level\": \"clean|low|medium|high|blocked\", \"risk_score\": 0.0-1.0, \"explanation\": \"brief\"}"

        user_msg = (
            f"Surface: {surface}\n"
            f"Protected names: {', '.join(self.config.protected_names) or 'none'}\n"
            f"Categories to check: {', '.join(self.config.check_categories)}\n"
            f"Fast path findings: score={fast_result.risk_score}, patterns={fast_result.matched_patterns[:2]}\n\n"
            f"Text to check:\n---\n{text[:4000]}\n---"
        )

        raw = self._call_llm(check_prompt, user_msg)

        if raw.startswith("[LLM unavailable"):
            return fast_result

        try:
            raw_clean = raw.strip().strip("```json").strip("```").strip()
            data = _json.loads(raw_clean)
        except Exception:
            return fast_result

        level_map = {
            "clean": ThreatLevel.CLEAN, "low": ThreatLevel.LOW,
            "medium": ThreatLevel.MEDIUM, "high": ThreatLevel.HIGH,
            "blocked": ThreatLevel.BLOCKED,
        }
        threat_level = level_map.get(data.get("threat_level", "medium"), ThreatLevel.MEDIUM)
        risk_score = float(data.get("risk_score", fast_result.risk_score))

        return ThreatResult(
            threat_level=threat_level,
            threat_types=fast_result.threat_types,
            risk_score=round(risk_score, 3),
            original_text=text,
            surface=surface,
            blocked=threat_level == ThreatLevel.BLOCKED,
            matched_patterns=fast_result.matched_patterns,
            explanation=data.get("explanation", fast_result.explanation),
            llm_used=True,
        )

    def _llm_sanitize(self, text: str, surface: str) -> str:
        """Ask the LLM to rewrite/redact the text. Returns sanitized text or 'BLOCKED'."""
        user_msg = (
            f"Surface: {surface}\n"
            f"Protected names (always redact): {', '.join(self.config.protected_names) or 'none'}\n"
            f"Categories to redact: {', '.join(self.config.check_categories)}\n\n"
            f"Text to sanitize:\n---\n{text[:4000]}\n---"
        )
        result = self._call_llm(_LLM_SYSTEM_PROMPT, user_msg)
        if result.startswith("[LLM unavailable"):
            return "[LLM_UNAVAILABLE]"
        return result.strip()

    def _regex_redact(self, text: str, fast_result: ThreatResult) -> str:
        """Fallback: apply crude regex redactions when LLM is unavailable."""
        redacted = text

        # Redact protected names
        for name_pattern in self._compiled_names:
            redacted = name_pattern.sub("[REDACTED]", redacted)

        # Redact obvious PII patterns (high-confidence only)
        for pattern, _, score, desc, cats in _COMPILED_PII:
            if score >= 0.75 and set(cats).intersection(self.config.check_categories):
                redacted = pattern.sub("[REDACTED]", redacted)

        return redacted

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        if score >= 0.90:
            return ThreatLevel.BLOCKED
        elif score >= 0.70:
            return ThreatLevel.HIGH
        elif score >= 0.45:
            return ThreatLevel.MEDIUM
        elif score >= 0.20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN
