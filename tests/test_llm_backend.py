"""
Tests for LLMBackend configuration — the security-critical bits:
  - TLS verification gating (only a self-hosted gateway may opt into insecure transport)
  - Gateway bearer-token precedence (must NOT leak the upstream provider secret)
  - Gateway base-URL normalization
No live network: requests.post is mocked where a call is exercised.
"""

import pytest

from jataayu.core.engine import LLMBackend

# Env vars that steer LLMBackend; cleared before every test so the process
# environment cannot bleed into assertions.
_ENV_KEYS = (
    "JATAAYU_LLM_BACKEND",
    "JATAAYU_LLM_MODEL",
    "JATAAYU_LLM_BASE_URL",
    "JATAAYU_LLM_API_KEY",
    "JATAAYU_GATEWAY_BASE_URL",
    "JATAAYU_GATEWAY_TOKEN",
    "JATAAYU_GATEWAY_INSECURE",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _openai_payload():
    return {"choices": [{"message": {"content": "ok"}}]}


# ---------------------------------------------------------------------------
# TLS verification gating
# ---------------------------------------------------------------------------


class TestTLSGating:
    def _capture_verify(self, monkeypatch, backend, base_url):
        captured = {}

        def fake_post(url, **kwargs):
            captured["verify"] = kwargs.get("verify")
            captured["url"] = url
            return _FakeResponse(_openai_payload())

        import requests

        monkeypatch.setattr(requests, "post", fake_post)
        b = LLMBackend(backend=backend, base_url=base_url, api_key="tok")
        b.call("sys", "user")
        return captured

    def test_openai_always_verifies_even_with_insecure_flag(self, monkeypatch):
        monkeypatch.setenv("JATAAYU_GATEWAY_INSECURE", "true")
        cap = self._capture_verify(monkeypatch, "openai", "https://api.openai.com")
        assert cap["verify"] is True

    def test_gateway_no_flag_verifies(self, monkeypatch):
        cap = self._capture_verify(monkeypatch, "gateway", "https://gw")
        assert cap["verify"] is True

    def test_gateway_insecure_flag_disables_verify(self, monkeypatch):
        monkeypatch.setenv("JATAAYU_GATEWAY_INSECURE", "true")
        cap = self._capture_verify(monkeypatch, "gateway", "https://gw")
        assert cap["verify"] is False

    def test_gateway_insecure_flag_tolerates_whitespace(self, monkeypatch):
        # A padded env value (" true ") must still be recognized as truthy.
        monkeypatch.setenv("JATAAYU_GATEWAY_INSECURE", " true ")
        cap = self._capture_verify(monkeypatch, "gateway", "https://gw")
        assert cap["verify"] is False


# ---------------------------------------------------------------------------
# Gateway bearer-token precedence
# ---------------------------------------------------------------------------


class TestGatewayTokenPrecedence:
    # A gateway backend resolves its base URL at construction, so these set it to let
    # construction succeed; the assertions are purely about which token wins.
    def test_explicit_api_key_wins_over_both_env(self, monkeypatch):
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", "https://gw")
        monkeypatch.setenv("JATAAYU_GATEWAY_TOKEN", "gw-env")
        monkeypatch.setenv("JATAAYU_LLM_API_KEY", "sk-provider")
        b = LLMBackend(backend="gateway", api_key="explicit")
        assert b._gateway_token() == "explicit"

    def test_gateway_token_env_used_when_no_explicit_arg(self, monkeypatch):
        monkeypatch.setenv("JATAAYU_LLM_BACKEND", "gateway")
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", "https://gw")
        monkeypatch.setenv("JATAAYU_GATEWAY_TOKEN", "gw-real")
        b = LLMBackend()
        assert b._gateway_token() == "gw-real"

    def test_llm_api_key_env_does_not_override_gateway_token(self, monkeypatch):
        # The reviewer's exact failure: the upstream provider secret must NOT become the bearer.
        monkeypatch.setenv("JATAAYU_LLM_BACKEND", "gateway")
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", "https://gw")
        monkeypatch.setenv("JATAAYU_LLM_API_KEY", "sk-wrong")
        monkeypatch.setenv("JATAAYU_GATEWAY_TOKEN", "gw-real")
        b = LLMBackend()
        assert b._gateway_token() == "gw-real"

    def test_llm_api_key_env_alone_is_not_a_gateway_token(self, monkeypatch):
        # Only the provider secret is present — must raise, never leak it to the gateway.
        monkeypatch.setenv("JATAAYU_LLM_BACKEND", "gateway")
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", "https://gw")
        monkeypatch.setenv("JATAAYU_LLM_API_KEY", "sk-wrong")
        b = LLMBackend()
        with pytest.raises(RuntimeError):
            b._gateway_token()

    def test_no_token_anywhere_raises(self, monkeypatch):
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", "https://gw")
        b = LLMBackend(backend="gateway")
        with pytest.raises(RuntimeError):
            b._gateway_token()


# ---------------------------------------------------------------------------
# Gateway base-URL normalization
# ---------------------------------------------------------------------------


class TestGatewayURLNormalization:
    @pytest.mark.parametrize(
        "given,expected",
        [
            ("https://gw/v1", "https://gw"),
            ("https://gw/v1/", "https://gw"),
            ("https://gw", "https://gw"),
            ("https://gw/apiv1", "https://gw/apiv1"),
            ("https://apiv1", "https://apiv1"),
        ],
    )
    def test_normalization(self, monkeypatch, given, expected):
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", given)
        b = LLMBackend(backend="gateway", api_key="tok")
        assert b._gateway_url() == expected

    def test_unset_base_url_raises(self, monkeypatch):
        # Unset gateway base URL raises at construction (base_url is resolved eagerly).
        with pytest.raises(RuntimeError):
            LLMBackend(backend="gateway", api_key="tok")

    def test_gateway_default_url_reads_env(self, monkeypatch):
        # base_url is resolved at construction via _default_url → _gateway_url.
        monkeypatch.setenv("JATAAYU_GATEWAY_BASE_URL", "https://gw/v1")
        b = LLMBackend(backend="gateway", api_key="tok")
        assert b.base_url == "https://gw"


# ---------------------------------------------------------------------------
# base_url normalization applies regardless of source (openai + gateway)
# ---------------------------------------------------------------------------


class TestBaseURLNormalizationAllSources:
    def test_gateway_explicit_arg_is_normalized(self):
        # Copilot's real bug: an explicit base_url= arg was never stripped, so
        # _call_openai_compat doubled to /v1/v1/… → 404.
        b = LLMBackend(backend="gateway", base_url="https://x/v1", api_key="tok")
        assert b.base_url == "https://x"

    @pytest.mark.parametrize("backend", ["gateway", "openai"])
    def test_generic_env_base_url_is_normalized(self, monkeypatch, backend):
        monkeypatch.setenv("JATAAYU_LLM_BASE_URL", "https://x/v1")
        b = LLMBackend(backend=backend, api_key="tok")
        assert b.base_url == "https://x"

    def test_openai_explicit_arg_is_normalized(self):
        b = LLMBackend(backend="openai", base_url="https://api.example/v1")
        assert b.base_url == "https://api.example"

    def test_no_v1_segment_left_untouched(self):
        b = LLMBackend(backend="openai", base_url="https://x")
        assert b.base_url == "https://x"

    def test_non_segment_apiv1_is_not_stripped(self):
        # /apiv1 is not a /v1 path segment; it must survive verbatim.
        b = LLMBackend(backend="openai", base_url="https://x/apiv1")
        assert b.base_url == "https://x/apiv1"

    @pytest.mark.parametrize("backend", ["ollama", "anthropic"])
    def test_other_backends_base_url_untouched(self, backend):
        # These build different request paths; a trailing /v1 must be preserved.
        b = LLMBackend(backend=backend, base_url="https://x/v1")
        assert b.base_url == "https://x/v1"


# ---------------------------------------------------------------------------
# Non-gateway backends construct without any gateway env
# ---------------------------------------------------------------------------


class TestOtherBackendsConstruct:
    @pytest.mark.parametrize("backend", ["ollama", "openai", "anthropic"])
    def test_construct_without_gateway_env(self, backend):
        b = LLMBackend(backend=backend)
        assert b.backend == backend
        assert b.base_url  # a default URL is resolved, no RuntimeError
