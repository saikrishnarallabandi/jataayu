"""
JataayuEngine — base class for Jataayu guards.

Provides:
  - Surface profile resolution
  - LLM backend configuration (Ollama or API)
  - Common utility methods
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional

from jataayu.core.threat import ThreatResult
from jataayu.surfaces.profiles import SURFACE_PROFILES


def _normalize_openai_compat_base_url(url: str) -> str:
    """Reduce an OpenAI-compatible base URL to the host root.

    _call_openai_compat appends /v1/chat/completions, so the base must NOT already
    carry /v1 — users commonly set …/v1 (the endpoint they see), which would double
    the path to /v1/v1/… → 404. Strip any trailing slashes and a single trailing
    case-insensitive /v1 segment; both https://gw and https://gw/v1 collapse to the
    same base. Idempotent, so it is safe to apply more than once.
    """
    url = url.rstrip("/")
    if url.lower().endswith("/v1"):
        url = url[: -len("/v1")].rstrip("/")
    return url


class LLMBackend:
    """
    Configurable LLM backend for Jataayu guards.

    Priority:
      1. Explicitly passed config
      2. JATAAYU_LLM_BACKEND env var (ollama | openai | anthropic | gateway)
      3. Default: ollama at localhost:11434
    """

    BACKENDS = ("ollama", "openai", "anthropic", "gateway")

    def __init__(
        self,
        backend: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.backend = backend or os.environ.get("JATAAYU_LLM_BACKEND", "ollama")
        self.model = model or os.environ.get("JATAAYU_LLM_MODEL", self._default_model())
        self.base_url = base_url or os.environ.get("JATAAYU_LLM_BASE_URL") or self._default_url()
        # Normalize regardless of source: base_url may arrive from the constructor arg, the
        # generic JATAAYU_LLM_BASE_URL env, or a backend default. _call_openai_compat appends
        # /v1/…, so any /v1 the caller included must be stripped here — not just on the gateway
        # env path. Only the OpenAI-compatible transports build that path; ollama/anthropic use
        # different suffixes and must keep their base URL verbatim.
        if self.backend in ("openai", "gateway"):
            self.base_url = _normalize_openai_compat_base_url(self.base_url)
        # Keep the raw constructor arg BEFORE the env fallback: the gateway token path must be able
        # to tell a programmatically-passed key from one sourced from JATAAYU_LLM_API_KEY (which is
        # the upstream provider secret, NOT the gateway bearer). See _gateway_token.
        self._explicit_api_key = api_key or ""
        self.api_key = api_key or os.environ.get("JATAAYU_LLM_API_KEY", "")

    def _default_model(self) -> str:
        defaults = {
            "ollama": "llama3",
            "openai": "gpt-4o-mini",
            "anthropic": "claude-haiku-4-5",
            "gateway": "anthropic/claude-sonnet-5",
        }
        return defaults.get(self.backend, "llama3")

    def _default_url(self) -> str:
        if self.backend == "gateway":
            return self._gateway_url()
        defaults = {
            "ollama": "http://localhost:11434",
            # base URL is the host root; _call_openai_compat appends /v1/chat/completions.
            # (Must NOT include /v1 here or the request path doubles to /v1/v1/… → 404.)
            "openai": "https://api.openai.com",
            "anthropic": "https://api.anthropic.com",
        }
        return defaults.get(self.backend, "http://localhost:11434")

    def _gateway_url(self) -> str:
        url = os.environ.get("JATAAYU_GATEWAY_BASE_URL", "")
        if not url:
            raise RuntimeError(
                "gateway backend selected but JATAAYU_GATEWAY_BASE_URL is not set"
            )
        return _normalize_openai_compat_base_url(url)

    def _gateway_token(self) -> str:
        # Gateway bearer precedence:
        #   1. Explicit constructor api_key (programmatic config, e.g. PrivacyConfig.llm_token) — wins.
        #   2. JATAAYU_GATEWAY_TOKEN env — the gateway-specific secret.
        #   3. Otherwise raise.
        # Deliberately does NOT fall back to the env-sourced JATAAYU_LLM_API_KEY: that is the
        # upstream provider secret (e.g. sk-ant-…), and sending it to the self-hosted gateway would
        # both break gateway auth and leak the provider key over the (optionally insecure) channel.
        token = self._explicit_api_key or os.environ.get("JATAAYU_GATEWAY_TOKEN", "")
        if not token:
            raise RuntimeError(
                "gateway backend selected but no token provided "
                "(pass api_key or set JATAAYU_GATEWAY_TOKEN)"
            )
        return token

    def call(self, system_prompt: str, user_message: str, max_tokens: int = 1024) -> str:
        """
        Call the configured LLM and return the response text.
        Raises RuntimeError if the backend is unavailable.
        """
        if self.backend == "ollama":
            return self._call_ollama(system_prompt, user_message, max_tokens)
        elif self.backend in ("openai", "gateway"):
            return self._call_openai_compat(system_prompt, user_message, max_tokens)
        elif self.backend == "anthropic":
            return self._call_anthropic(system_prompt, user_message, max_tokens)
        else:
            raise ValueError(f"Unknown backend: {self.backend!r}")

    def _call_ollama(self, system_prompt: str, user_message: str, max_tokens: int) -> str:
        import requests
        resp = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()

    def _call_openai_compat(self, system_prompt: str, user_message: str, max_tokens: int) -> str:
        import requests

        headers = {"Content-Type": "application/json"}
        if self.backend == "gateway":
            headers["Authorization"] = f"Bearer {self._gateway_token()}"
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        # TLS verification is ON by default. The openai backend (talking to api.openai.com) ALWAYS
        # verifies — there is no opt-out. Only a self-hosted gateway may opt into insecure transport,
        # for self-signed localhost certs, and only via an explicit env flag.
        verify = True
        if self.backend == "gateway" and os.environ.get(
            "JATAAYU_GATEWAY_INSECURE", ""
        ).strip().lower() in ("1", "true", "yes"):
            verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.post(
            f"{self.base_url}/v1/chat/completions",
            headers=headers,
            json={
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            },
            verify=verify,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    def _call_anthropic(self, system_prompt: str, user_message: str, max_tokens: int) -> str:
        import requests
        resp = requests.post(
            f"{self.base_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_message}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"].strip()


class JataayuEngine(ABC):
    """
    Abstract base class for Jataayu guards.

    Subclasses implement check() with their guard logic.
    Provides surface profile lookup and LLM backend access.
    """

    def __init__(
        self,
        llm_backend: Optional[LLMBackend] = None,
        use_llm: bool = True,
        llm_threshold: float = 0.4,
    ):
        """
        Args:
            llm_backend: LLM backend config. Defaults to env-configured backend.
            use_llm: Whether to use LLM slow path. Default True.
            llm_threshold: Risk score above which to invoke LLM. Default 0.4.
        """
        self.llm = llm_backend or LLMBackend()
        self.use_llm = use_llm
        self.llm_threshold = llm_threshold

    def get_surface_profile(self, surface: str) -> dict:
        """Resolve a surface name to its profile dict."""
        return SURFACE_PROFILES.get(surface, {
            "trust_level": "medium",
            "description": f"Unknown surface: {surface}",
            "watch_for": [],
        })

    def is_strict_inbound(self, surface: str) -> bool:
        return self.get_surface_profile(surface).get("inbound_strict", False)

    def is_strict_outbound(self, surface: str) -> bool:
        return self.get_surface_profile(surface).get("outbound_strict", False)

    @abstractmethod
    def check(self, text: str, surface: str = "unknown") -> ThreatResult:
        """
        Evaluate text for threats.

        Args:
            text: Content to evaluate.
            surface: The surface context (e.g., "github-issue", "group-chat").

        Returns:
            ThreatResult with findings.
        """
        ...

    def _call_llm(self, system_prompt: str, user_message: str) -> str:
        """Call the LLM backend. Returns empty string on failure."""
        try:
            return self.llm.call(system_prompt, user_message)
        except Exception as e:
            return f"[LLM unavailable: {e}]"
