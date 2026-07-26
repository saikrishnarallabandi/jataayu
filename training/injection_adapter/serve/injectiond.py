"""injectiond — a warm HTTP sidecar that serves the Jataayu v0.1 injection score.

Why this exists: the detector is base Qwen/Qwen3.5-0.8B + the release LoRA adapter loaded
in fp32, and loading that costs seconds per process. The live message path cannot shell out
per turn, so the model must stay resident: this file keeps it warm and answers P(INJECTION)
over HTTP in a few ms.

The inference is NOT reimplemented here. Everything scoring-related — the fixed judge framing,
the chat template with enable_thinking=False, the in-context label-id derivation, and the
two-class softmax P(INJECTION) at the final position — is imported verbatim from
training/injection_adapter/code/injscore.py, the same code the training target and the
leaderboard eval use. This file is only the HTTP wrapper.

Design, mirrored on the smriti sidecar (project_smriti/src/smriti/serve.py):

- **Warm and non-blocking start.** The HTTP server binds and starts serving IMMEDIATELY, while
  the model loads on a background thread. /health returns 503 until the model is ready, so a
  supervisor can wait on it and the caller can tell "not ready yet" from "down".
- **Serialized inference.** One GPU, one model; concurrent forward passes are serialized behind
  a lock. Recall the caller (the jataayu plugin) fails OPEN on any error, so /score never returns
  a 500 — a failure inside scoring answers 200 with {"p_injection": null, "error": ...}.
- **Stdlib only.** No web framework; a single-model scorer is not worth one.

Run (Pascal / 1080 Ti -> fp32 is required; the Qwen3.5 linear-attn fp16 kernel crashes):

    CUDA_VISIBLE_DEVICES=1 /home/user/envs/jataayu/bin/python \
        training/injection_adapter/serve/injectiond.py

Env: /home/user/envs/jataayu (torch 2.6.0+cu124, transformers @ git main, peft 0.19.1).
The shared orchestrator_env cannot load model_type qwen3_5.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent  # training/injection_adapter/serve
CODE = HERE.parent / "code"  # training/injection_adapter/code
RELEASE = HERE.parent / "release" / "Jataayu.promptinjection.v0.1"
sys.path.insert(0, str(CODE))
import injscore  # noqa: E402  -- shared prompt-framing + first-token scoring (do not reimplement)

log = logging.getLogger("injectiond")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18902  # free: NOT 18789 gateway / 18800 / 18901 smriti
DEFAULT_BASE = "Qwen/Qwen3.5-0.8B"
DEFAULT_MAX_CHARS = 4000  # hard cap on scored text, to bound latency


class Scorer:
    """Holds the warm model. Loaded once on a background thread; inference is serialized."""

    def __init__(self, base: str, adapter: str, device: str | None) -> None:
        self.base = base
        self.adapter = adapter
        self.device = device  # None -> resolved at load time
        self.ready = False
        self.load_error: str | None = None
        self.load_seconds: float | None = None
        self.pos_id: int | None = None
        self.neg_id: int | None = None
        self._model: Any = None
        self._tok: Any = None
        self._lock = threading.Lock()  # one GPU, one model: serialize forward passes

    def load(self) -> None:
        """Load base + release adapter in fp32 and derive the label ids. Sets ready=True on
        success; on failure records load_error and leaves ready=False (so /health stays 503
        and /score reports the error rather than crashing the process)."""
        t0 = time.time()
        try:
            import torch
            from transformers import AutoTokenizer

            if self.device is None:
                self.device = "cuda" if torch.cuda.is_available() else "cpu"
            dev = self.device

            tok = AutoTokenizer.from_pretrained(self.base, trust_remote_code=True)
            if tok.pad_token is None:
                tok.pad_token = tok.eos_token

            # fp32 on Pascal: the Qwen3.5 linear-attn fp16 kernel crashes on a 1080 Ti.
            kwargs = dict(dtype=torch.float32, trust_remote_code=True)
            if dev.startswith("cuda"):
                kwargs["device_map"] = {"": 0}  # CUDA_VISIBLE_DEVICES pins the physical GPU
            try:
                from transformers import AutoModelForCausalLM

                model = AutoModelForCausalLM.from_pretrained(self.base, **kwargs)
            except (ValueError, KeyError):
                from transformers import AutoModelForImageTextToText

                model = AutoModelForImageTextToText.from_pretrained(self.base, **kwargs)
            if not dev.startswith("cuda"):
                model = model.to(dev)

            from peft import PeftModel

            model = PeftModel.from_pretrained(model, str(self.adapter))
            model.eval()

            self.pos_id, self.neg_id = injscore.label_first_token_ids(tok)
            self._tok = tok
            self._model = model
            self.load_seconds = time.time() - t0
            self.ready = True
            log.info(
                "ready: base=%s adapter=%s device=%s load=%.1fs INJECTION id=%s BENIGN id=%s",
                self.base,
                self.adapter,
                dev,
                self.load_seconds,
                self.pos_id,
                self.neg_id,
            )
        except Exception as exc:  # noqa: BLE001 - never crash the process; report via /health & /score
            self.load_error = str(exc)
            log.exception("model load failed; /health will report 503")

    def score(self, text: str) -> float:
        """Two-class softmax P(INJECTION) for one text. Serialized behind the model lock."""
        if not self.ready:
            raise RuntimeError(self.load_error or "model not loaded yet")
        with self._lock:
            out = injscore.injection_scores(
                self._model, self._tok, [text], self.pos_id, self.neg_id, device=self.device
            )
        return float(out[0]["score"])

    def health(self) -> dict:
        return {
            "ok": self.ready,
            "model_loaded": self.ready,
            "base": self.base,
            "adapter": str(self.adapter),
            "device": self.device,
            "load_seconds": self.load_seconds,
            "load_error": self.load_error,
        }


def _handler(scorer: Scorer, max_chars: int) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            if self.path == "/health":
                self._send(200 if scorer.ready else 503, scorer.health())
            else:
                self._send(404, {"error": f"no such route: {self.path}"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            if self.path != "/score":
                self._send(404, {"error": f"no such route: {self.path}"})
                return
            # Everything inside /score answers 200. The caller (the jataayu plugin) fails OPEN,
            # but a 500 with an HTML body is harder to degrade against than a clean null.
            t0 = time.perf_counter()
            try:
                length = int(self.headers.get("Content-Length") or 0)
                params = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(params, dict):
                    raise ValueError("expected a JSON object body")
                text = params.get("text")
                if text is None:
                    text = ""
                text = str(text)
                capped = len(text) > max_chars
                if capped:
                    text = text[:max_chars]
                p = scorer.score(text)
                self._send(
                    200,
                    {
                        "p_injection": p,
                        "label": "INJECTION" if p >= 0.5 else "BENIGN",
                        "ms": (time.perf_counter() - t0) * 1000.0,
                        "capped": capped,
                    },
                )
            except Exception as exc:  # noqa: BLE001 - never 500; hand the caller a null it can fail open on
                self._send(200, {"p_injection": None, "error": str(exc)})

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug(fmt, *args)

    return Handler


def serve(
    host: str, port: int, device: str | None, max_chars: int, base: str, adapter: str
) -> None:
    scorer = Scorer(base, adapter, device)
    # Load on a background thread so the HTTP server can bind and answer /health (503) at once.
    threading.Thread(target=scorer.load, name="injectiond-load", daemon=True).start()

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server((host, port), _handler(scorer, max_chars))
    print(
        f"[injectiond] listening on http://{host}:{port} (loading model, cap={max_chars} chars)",
        flush=True,
    )
    log.info("injectiond listening on http://%s:%d (loading model)", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("INJECTIOND_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    ap = argparse.ArgumentParser(description="Jataayu injection-classifier HTTP sidecar")
    ap.add_argument("--host", default=os.environ.get("INJECTIOND_HOST", DEFAULT_HOST))
    ap.add_argument(
        "--port", type=int, default=int(os.environ.get("INJECTIOND_PORT", DEFAULT_PORT))
    )
    ap.add_argument(
        "--device",
        default=os.environ.get("INJECTIOND_DEVICE") or None,
        help="cuda|cpu|cuda:N (default: cuda if available else cpu)",
    )
    ap.add_argument(
        "--max-chars",
        type=int,
        default=int(os.environ.get("INJECTIOND_MAX_CHARS", DEFAULT_MAX_CHARS)),
    )
    ap.add_argument("--base", default=os.environ.get("INJECTIOND_BASE", DEFAULT_BASE))
    ap.add_argument("--adapter", default=os.environ.get("INJECTIOND_ADAPTER", str(RELEASE)))
    args = ap.parse_args()
    serve(args.host, args.port, args.device, args.max_chars, args.base, args.adapter)
    return 0


if __name__ == "__main__":
    sys.exit(main())
