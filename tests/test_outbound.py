"""
Tests for Jataayu OutboundGuard — PII and privacy leakage detection.
No LLM required (use_llm=False throughout).
"""
import pytest
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig
from jataayu.core.threat import ThreatLevel, ThreatType


@pytest.fixture
def guard():
    return OutboundGuard(PrivacyConfig(use_llm=False))


@pytest.fixture
def guard_with_names():
    config = PrivacyConfig(
        protected_names=["Alice", "Bobby"],
        use_llm=False,
    )
    return OutboundGuard(config)


# ---------------------------------------------------------------------------
# PII / privacy violations — should be caught
# ---------------------------------------------------------------------------

class TestPIIDetection:
    def test_child_school_info(self, guard):
        result = guard.check(
            "My daughter goes to Lincoln Elementary and is in 2nd grade.",
            surface="group-chat",
        )
        assert not result.is_safe, f"Child school info should be flagged: {result.explanation}"

    def test_child_age(self, guard):
        result = guard.check(
            "My son is 4 years old and just started preschool.",
            surface="discord-channel",
        )
        assert not result.is_safe

    def test_salary_disclosure(self, guard):
        result = guard.check(
            "John earns $185,000 a year and is looking for a new job.",
            surface="group-chat",
        )
        assert not result.is_safe

    def test_credit_card_number(self, guard):
        result = guard.check(
            "Card: 4111 1111 1111 1111",
            surface="email",
        )
        assert not result.is_safe
        assert ThreatType.PRIVACY_VIOLATION in result.threat_types

    def test_home_address(self, guard):
        result = guard.check(
            "She lives at 123 Maple Street, apartment 4B.",
            surface="group-chat",
        )
        assert not result.is_safe

    def test_phone_number(self, guard):
        result = guard.check(
            "Call me at 555-867-5309 for more details.",
            surface="discord-channel",
        )
        assert not result.is_safe

    def test_health_information(self, guard):
        result = guard.check(
            "He was diagnosed with diabetes last year and is on medication.",
            surface="group-chat",
        )
        assert not result.is_safe

    def test_protected_name_direct(self, guard_with_names):
        result = guard_with_names.check(
            "I asked Alice to review the PR but she hasn't responded.",
            surface="github-comment",
        )
        assert not result.is_safe, "Protected name should be flagged"


# ---------------------------------------------------------------------------
# Clean content — should NOT be flagged
# ---------------------------------------------------------------------------

class TestCleanOutbound:
    def test_clean_technical_content(self, guard):
        result = guard.check(
            "The API returns a JSON object with the user's session token and preferences.",
            surface="group-chat",
        )
        assert result.is_safe, f"Clean technical content flagged: {result.explanation}"

    def test_clean_trading_strategy(self, guard):
        result = guard.check(
            "The momentum strategy buys SPY when RSI crosses above 30 on the daily chart.",
            surface="discord-channel",
        )
        assert result.is_safe, f"Clean trading content flagged: {result.explanation}"

    def test_clean_code_review(self, guard):
        result = guard.check(
            "Fixed the null pointer exception in the auth module. See PR #142.",
            surface="github-comment",
        )
        assert result.is_safe, f"Clean code review flagged: {result.explanation}"

    def test_empty_input(self, guard):
        result = guard.check("", surface="group-chat")
        assert result.is_safe
        assert result.threat_level == ThreatLevel.CLEAN

    def test_direct_message_relaxed(self, guard):
        """Direct messages have lower risk multiplier."""
        result = guard.check(
            "Call me at 555-867-5309 for more details.",
            surface="direct-message",
        )
        # Even with a phone number, direct-message surface should be less strict
        # Score reduced by 0.6 multiplier: 0.60 * 0.6 = 0.36 → LOW
        assert result.risk_score < 0.5


# ---------------------------------------------------------------------------
# Sanitize tests (regex fallback, no LLM)
# ---------------------------------------------------------------------------

class TestSanitize:
    def test_sanitize_protected_name(self, guard_with_names):
        text = "Alice will present her findings at the meeting."
        sanitized = guard_with_names.sanitize(text, surface="group-chat")
        assert "Alice" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_credit_card(self, guard):
        text = "The card number is 4111 1111 1111 1111, please don't share."
        sanitized = guard.sanitize(text, surface="email")
        assert "4111" not in sanitized or "[REDACTED]" in sanitized

    def test_sanitize_clean_passthrough(self, guard):
        text = "The deployment completed successfully at 14:32 UTC."
        sanitized = guard.sanitize(text, surface="group-chat")
        assert sanitized == text, "Clean text should pass through unchanged"


# ---------------------------------------------------------------------------
# Surface profile tests
# ---------------------------------------------------------------------------

class TestSurfaceProfiles:
    def test_surface_profiles_exist(self):
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        assert "github-issue" in SURFACE_PROFILES
        assert "group-chat" in SURFACE_PROFILES
        assert "direct-message" in SURFACE_PROFILES
        assert "web-content" in SURFACE_PROFILES
        assert "email" in SURFACE_PROFILES

    def test_surface_profile_structure(self):
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        for name, profile in SURFACE_PROFILES.items():
            assert "trust_level" in profile, f"Profile {name} missing trust_level"
            assert "inbound_strict" in profile, f"Profile {name} missing inbound_strict"
            assert "outbound_strict" in profile, f"Profile {name} missing outbound_strict"

    def test_github_is_low_trust(self):
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        assert SURFACE_PROFILES["github-issue"]["trust_level"] == "low"

    def test_direct_message_is_high_trust(self):
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        assert SURFACE_PROFILES["direct-message"]["trust_level"] == "high"
