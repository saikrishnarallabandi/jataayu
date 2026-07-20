"""
Tests for Issue #5 — OutboundGuard credential leak detection.
Covers Aguara CRED_001-017 patterns.
"""
import pytest
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig
from jataayu.core.threat import ThreatType


@pytest.fixture
def guard():
    return OutboundGuard(PrivacyConfig(use_llm=False, check_credentials=True))


@pytest.fixture
def guard_no_creds():
    return OutboundGuard(PrivacyConfig(use_llm=False, check_credentials=False))


class TestOpenAIKey:
    def test_openai_api_key_detected(self, guard):
        result = guard.check("Use this key: sk-abc123XYZdefgh456IJKlmno789", surface="group-chat")
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_openai_key_in_code_block(self, guard):
        result = guard.check(
            "Here's the config:\n```\nopenai_key = sk-abc123ABCD1234567890XYZ\n```",
            surface="github-comment",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types


class TestAnthropicKey:
    def test_anthropic_api_key_detected(self, guard):
        result = guard.check(
            "API key: sk-ant-api03-abcdefghijklmnop123456789",
            surface="group-chat",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types


class TestAWSKeys:
    def test_aws_access_key_detected(self, guard):
        result = guard.check(
            "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE",
            surface="group-chat",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_aws_key_in_export(self, guard):
        result = guard.check(
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            surface="discord-channel",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types


class TestGitHubToken:
    def test_github_pat_detected(self, guard):
        result = guard.check(
            "GitHub token: ghp_1234567890abcdefghijABCDEFGHIJ01234",
            surface="group-chat",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_github_oauth_detected(self, guard):
        result = guard.check(
            "Token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
            surface="email",
        )
        assert not result.is_safe


class TestPrivateKeys:
    def test_rsa_private_key_detected(self, guard):
        result = guard.check(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
            surface="group-chat",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_openssh_private_key_detected(self, guard):
        result = guard.check(
            "Key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...",
            surface="email",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_ec_private_key_detected(self, guard):
        result = guard.check(
            "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBl...",
            surface="discord-channel",
        )
        assert not result.is_safe


class TestDatabaseConnectionStrings:
    def test_postgres_connection_string(self, guard):
        result = guard.check(
            "DB_URL = postgresql://admin:supersecret@db.example.com:5432/mydb",
            surface="group-chat",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_mongodb_connection_string(self, guard):
        result = guard.check(
            "MONGODB_URI=mongodb://user:p@ssw0rd@cluster.mongodb.net/mydb",
            surface="github-comment",
        )
        assert not result.is_safe

    def test_redis_connection_with_password(self, guard):
        result = guard.check(
            "REDIS_URL=redis://default:redispass123@localhost:6379",
            surface="email",
        )
        assert not result.is_safe


class TestWebhooks:
    def test_slack_webhook_detected(self, guard):
        # Fake test webhook — structurally valid but obviously not a real token
        fake_webhook = "https://hooks.slack.com/services/" + "T0TEST0000/B0TEST0000/jataayuTestTokenFakeNotReal0x01"
        result = guard.check(f"Slack webhook: {fake_webhook}", surface="group-chat")
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_discord_webhook_detected(self, guard):
        # Fake test webhook — not a real Discord webhook token
        fake_token = "jataayuFakeTestToken" + "NotRealWebhookXYZ01234567"
        result = guard.check(
            f"Discord webhook: https://discord.com/api/webhooks/123456789/{fake_token}",
            surface="email",
        )
        assert not result.is_safe


class TestStripeKeys:
    def test_stripe_secret_key(self, guard):
        # Fake test key — structurally valid Stripe format but obviously not real
        fake_key = "sk_live_" + "JataayuFakeNotRealTestKey1234Abcd"
        result = guard.check(f"Stripe key: {fake_key}", surface="group-chat")
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_stripe_test_key(self, guard):
        # Fake test key — not a real Stripe key
        fake_key = "sk_test_" + "JataayuFakeTestKeyNotRealABCDEFGH"
        result = guard.check(f"Test with: {fake_key}", surface="discord-channel")
        assert not result.is_safe


class TestJWTTokens:
    def test_jwt_token_detected(self, guard):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = guard.check(f"Auth: {jwt}", surface="group-chat")
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types


class TestBearerTokens:
    def test_bearer_token_in_header(self, guard):
        result = guard.check(
            "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.payload.signature",
            surface="group-chat",
        )
        assert not result.is_safe


class TestGenericAPIKeys:
    def test_generic_api_key_assignment(self, guard):
        result = guard.check(
            "api_key = 1234567890abcdefghijklmnop",
            surface="discord-channel",
        )
        assert not result.is_safe
        assert ThreatType.CREDENTIAL_LEAK in result.threat_types

    def test_access_token_assignment(self, guard):
        result = guard.check(
            "access_token: ghijklmnopqrstuvwxyz12345678",
            surface="group-chat",
        )
        assert not result.is_safe


class TestHighEntropy:
    def test_high_entropy_string_detected(self):
        guard = OutboundGuard(PrivacyConfig(
            use_llm=False,
            check_credentials=True,
            check_high_entropy=True,
        ))
        # This is a realistic secret: high entropy, alphanumeric, >= 40 chars
        secret = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB"  # 41 chars, high entropy
        result = guard.check(f"config = {secret}", surface="group-chat")
        assert not result.is_safe

    def test_high_entropy_disabled_by_default(self, guard):
        """High entropy check is OFF by default — no false positives on hashes."""
        # This is a realistic git SHA — should NOT be flagged when entropy check is off
        git_sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        result = guard.check(f"commit: {git_sha}", surface="group-chat")
        # Should not flag a plain git sha when high_entropy is disabled
        # (it won't match specific patterns unless it resembles a known key)
        # Just check no CREDENTIAL_LEAK if all specific patterns don't match
        cred_matched = [m for m in result.matched_patterns if "CRED_" in m]
        assert len(cred_matched) == 0, f"Git SHA falsely flagged: {cred_matched}"


class TestCredentialCheckDisabled:
    def test_api_key_not_flagged_when_creds_disabled(self, guard_no_creds):
        result = guard_no_creds.check(
            "sk-abc123ABCD1234567890XYZdefghijklmno",
            surface="group-chat",
        )
        # When check_credentials=False, credential patterns should not fire
        cred_types = [t for t in result.threat_types if t == ThreatType.CREDENTIAL_LEAK]
        assert len(cred_types) == 0

    def test_pii_still_detected_when_creds_disabled(self, guard_no_creds):
        result = guard_no_creds.check(
            "My daughter is 5 years old.",
            surface="group-chat",
        )
        assert not result.is_safe


class TestDisabledCredRules:
    def test_disabled_rule_not_flagged(self):
        guard = OutboundGuard(PrivacyConfig(
            use_llm=False,
            check_credentials=True,
            disabled_cred_rules=["CRED_004"],  # Disable generic API key
        ))
        result = guard.check(
            "api_key = 1234567890abcdefghijklmnop",
            surface="group-chat",
        )
        # CRED_004 disabled — should not be flagged by that rule
        cred_004_matches = [m for m in result.matched_patterns if "CRED_004" in m]
        assert len(cred_004_matches) == 0


class TestCleanContentNotFlaggedForCreds:
    def test_clean_code_not_flagged(self, guard):
        result = guard.check(
            "The function returns a UUID string like '550e8400-e29b-41d4-a716-446655440000'.",
            surface="discord-channel",
        )
        assert ThreatType.CREDENTIAL_LEAK not in result.threat_types, \
            f"UUID falsely flagged as credential: {result.matched_patterns}"

    def test_doc_string_not_flagged(self, guard):
        result = guard.check(
            "This API requires authentication. Pass your credentials securely.",
            surface="group-chat",
        )
        assert ThreatType.CREDENTIAL_LEAK not in result.threat_types

    def test_git_sha_not_flagged(self, guard):
        result = guard.check(
            "Latest commit: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            surface="discord-channel",
        )
        # git sha should not match specific key patterns
        cred_matches = [m for m in result.matched_patterns if "CRED_" in m]
        assert len(cred_matches) == 0, f"Git SHA flagged: {cred_matches}"
