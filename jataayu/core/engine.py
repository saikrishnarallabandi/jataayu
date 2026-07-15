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
        self.api_key = api_key or os.environ.get("JATAAYU_LLM_API_KEY", "")

    def _default_model(self) -> str:
        defaults = {
            "ollama": "llama3",
            "openai": "gpt-4o-mini",
            "anthropic": "claude-haiku-20240307",
            "gateway": "anthropic/claude-sonnet-4-6",
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
        return url

    def _gateway_token(self) -> str:
        token = os.environ.get("JATAAYU_GATEWAY_TOKEN", "")
        if not token:
            raise RuntimeError(
                "gateway backend selected but JATAAYU_GATEWAY_TOKEN is not set"
            )
        return token

    def call(self, system_prompt: str, user_message: str, max_tokens: int = 1024) -> str:
        """
        Call the configured LLM and return the response text.
        Raises RuntimeError if the backend is unavailable.
        """
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = {"Content-Type": "application/json"}
        if self.backend == "gateway":
            headers["Authorization"] = f"Bearer {self._gateway_token()}"
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

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
            verify=False,
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
