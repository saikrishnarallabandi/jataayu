"""
JataayuEngine — base class for Jataayu guards.

Provides:
  - Surface profile resolution
  - LLM backend configuration (Ollama or API)
  - Common utility methods
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from jataayu.core.threat import ThreatResult
from jataayu.surfaces.profiles import SURFACE_PROFILES


class LLMBackend:
    """
    Configurable LLM backend for Jataayu guards.

    Priority:
      1. Explicitly passed config
      2. JATAAYU_LLM_BACKEND env var (ollama | openai | anthropic | openclaw)
      3. Default: ollama at localhost:11434
    """

    BACKENDS = ("ollama", "openai", "anthropic", "openclaw")

    def __init__(
        self,
        backend: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.backend = backend or os.environ.get("JATAAYU_LLM_BACKEND", "ollama")
        self.model = model or os.environ.get("JATAAYU_LLM_MODEL", self._default_model())
        self.base_url = base_url or os.environ.get("JATAAYU_LLM_BASE_URL", self._default_url())
        self.api_key = api_key or os.environ.get("JATAAYU_LLM_API_KEY", "")

    def _default_model(self) -> str:
        defaults = {
            "ollama": "llama3",
            "openai": "gpt-4o-mini",
            "anthropic": "claude-haiku-20240307",
            "openclaw": "anthropic/claude-sonnet-4-6",
        }
        return defaults.get(self.backend, "llama3")

    def _default_url(self) -> str:
        defaults = {
            "ollama": "http://localhost:11434",
            "openai": "https://api.openai.com/v1",
            "anthropic": "https://api.anthropic.com",
            "openclaw": self._openclaw_url(),
        }
        return defaults.get(self.backend, "http://localhost:11434")

    def _openclaw_url(self) -> str:
        config_path = Path.home() / ".openclaw" / "openclaw.json"
        try:
            config = json.loads(config_path.read_text())
            port = config.get("gateway", {}).get("port", 18789)
            return f"https://localhost:{port}"
        except Exception:
            return "https://localhost:18789"

    def _openclaw_token(self) -> str:
        config_path = Path.home() / ".openclaw" / "openclaw.json"
        try:
            config = json.loads(config_path.read_text())
            return config.get("gateway", {}).get("auth", {}).get("token", "")
        except Exception:
            return ""

    def call(self, system_prompt: str, user_message: str, max_tokens: int = 1024) -> str:
        """
        Call the configured LLM and return the response text.
        Raises RuntimeError if the backend is unavailable.
        """
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if self.backend == "ollama":
            return self._call_ollama(system_prompt, user_message, max_tokens)
        elif self.backend in ("openai", "openclaw"):
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
        if self.backend == "openclaw":
            headers["Authorization"] = f"Bearer {self._openclaw_token()}"
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        base_url = self.base_url.rstrip("/")
        if base_url.endswith("/v1"):
            endpoint = f"{base_url}/chat/completions"
        else:
            endpoint = f"{base_url}/v1/chat/completions"

        resp = requests.post(
            endpoint,
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

    @staticmethod
    def _extract_json_payload(raw: str) -> str:
        """
        Extract JSON text from plain or fenced LLM responses.

        Supports:
        - Plain JSON: { ... }
        - Fenced JSON: ```json ... ``` or ``` ... ```
        """
        text = raw.strip()
        if not text.startswith("```"):
            return text

        lines = text.splitlines()
        if len(lines) < 3 or not lines[0].startswith("```"):
            return text

        for idx in range(len(lines) - 1, 0, -1):
            if lines[idx].strip().startswith("```"):
                return "\n".join(lines[1:idx]).strip()

        return text
