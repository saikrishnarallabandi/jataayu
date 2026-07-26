"""Backend-agnostic chat client for the synthesis generator.

Two backends:
  - openai : OpenAI-compatible /v1/chat/completions (the LiteLLM router that fronts the
             local qwen3.6:35b on gpu-host — the intended synthesis TEACHER). Reasoning is
             suppressed by appending "/no_think" to the user turn.
  - ollama : native /api/chat with think=false (reliable reasoning suppression + low latency;
             the fallback generator when dgx/router is unreachable).

The client only produces text; callers own prompt construction, JSON parsing and label logic.
Gold labels are set BY CONSTRUCTION in the synth scripts, never taken from generator output.
"""

import json
import os
import time
import urllib.request
import urllib.error

DEFAULT_TIMEOUT = 120


class LLMClient:
    def __init__(
        self,
        backend,
        base_url,
        model,
        temperature=0.7,
        timeout=DEFAULT_TIMEOUT,
        max_tokens=1024,
        retries=4,
        append_no_think=False,
        api_key=None,
    ):
        assert backend in ("openai", "ollama"), backend
        self.backend = backend
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.retries = retries
        # Qwen3-family reasoning models need "/no_think"; Qwen2.5-Instruct does NOT
        # (it would inject a spurious literal token). Off by default.
        self.append_no_think = append_no_think
        # Only the openai backend has an Authorization contract; ollama native takes none.
        self.api_key = api_key if backend == "openai" else None

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = "Bearer " + self.api_key
        return h

    def _post(self, path, payload):
        url = self.base_url + path
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def chat(self, system, user, temperature=None):
        """Return assistant text for a single (system, user) turn. Retries transient errors."""
        temp = self.temperature if temperature is None else temperature
        last_err = None
        for attempt in range(self.retries):
            try:
                if self.backend == "openai":
                    payload = {
                        "model": self.model,
                        "temperature": temp,
                        "max_tokens": self.max_tokens,
                        "messages": [
                            {"role": "system", "content": system},
                            {
                                "role": "user",
                                "content": user + ("\n\n/no_think" if self.append_no_think else ""),
                            },
                        ],
                    }
                    out = self._post("/chat/completions", payload)
                    return out["choices"][0]["message"]["content"] or ""
                else:  # ollama native
                    payload = {
                        "model": self.model,
                        "stream": False,
                        "think": False,
                        "options": {"temperature": temp, "num_predict": self.max_tokens},
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                    }
                    out = self._post("/api/chat", payload)
                    return out["message"]["content"] or ""
            except (
                urllib.error.URLError,
                KeyError,
                json.JSONDecodeError,
                TimeoutError,
                OSError,
            ) as e:
                last_err = e
                time.sleep(min(2**attempt, 15))
        raise RuntimeError(f"LLM chat failed after {self.retries} attempts: {last_err}")

    def probe(self):
        """Return (ok, detail). Cheap reachability check with a short generation."""
        try:
            txt = self.chat("You reply with one word.", "Say OK.", temperature=0)
            return True, txt.strip()[:80]
        except Exception as e:  # noqa: BLE001 - probe reports any failure
            return False, str(e)[:200]


def add_backend_args(parser):
    """Shared CLI flags so every synth script targets the same generator by default."""
    parser.add_argument(
        "--backend",
        choices=["openai", "ollama"],
        default="openai",
        help="openai = vast vLLM teacher over the autossh tunnel",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000/v1",
        help="vast teacher via tunnel: http://localhost:8000/v1",
    )
    parser.add_argument(
        "--model", default="teacher", help="served-model-name on the vast vLLM server"
    )
    parser.add_argument("--temperature", type=float, default=0.8)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--no-think", action="store_true", help="append /no_think (only for qwen3 reasoning models)"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="bearer token for a hosted openai-compatible API. Defaults to "
        "$ANTHROPIC_API_KEY, but ONLY for https base-urls (see "
        "resolve_api_key)",
    )


def resolve_api_key(args):
    """Bearer token for the openai backend, or None.

    An explicit --api-key always wins. The $ANTHROPIC_API_KEY fallback applies only to https
    base-urls: that env var is set on the dev boxes, and the four synth generators all default to
    --backend openai --base-url http://localhost:8000/v1, so an unconditional fallback would start
    attaching a live Authorization header to every existing local ollama/LiteLLM run — changing
    behavior that must stay byte-identical (LiteLLM 401s when a master_key is set) and putting the
    key on the wire in plaintext.
    """
    explicit = getattr(args, "api_key", None)
    if explicit:
        return explicit
    if getattr(args, "backend", None) == "openai" and str(
        getattr(args, "base_url", "")
    ).lower().startswith("https://"):
        return os.environ.get("ANTHROPIC_API_KEY") or None
    return None


def client_from_args(args):
    return LLMClient(
        args.backend,
        args.base_url,
        args.model,
        temperature=args.temperature,
        timeout=args.timeout,
        append_no_think=getattr(args, "no_think", False),
        api_key=resolve_api_key(args),
    )
