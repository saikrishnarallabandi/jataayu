#!/usr/bin/env python3
"""Tailnet demo server for the Jataayu prompt-injection classifier.

Serves injection_demo.html and proxies POST /api/score to the LOCAL injectiond
sidecar (127.0.0.1:18902). Same-origin, so the page has no CORS trouble, and it
reuses the already-warm model — no second load. Read-only: it forwards text to
/score and returns the JSON; it never changes anything.

Run:  python3 demo_server.py [--host <ip>] [--port 8874] [--sidecar http://127.0.0.1:18902]
"""
import argparse, json, os, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(HERE, "injection_demo.html")


class Handler(BaseHTTPRequestHandler):
    sidecar = "http://127.0.0.1:18902"

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html", "/demo"):
            try:
                with open(HTML, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, f"<pre>demo page missing: {e}</pre>", "text/html")
        elif self.path == "/healthz":
            self._send(200, json.dumps({"ok": True}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path != "/api/score":
            self._send(404, json.dumps({"error": "not found"}))
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b"{}"
            # forward verbatim to the sidecar /score
            req = urllib.request.Request(
                self.sidecar.rstrip("/") + "/score", data=raw,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15) as r:
                self._send(200, r.read())
        except urllib.error.URLError as e:
            # sidecar down / unreachable — report cleanly, never 500 the demo
            self._send(200, json.dumps({"p_injection": None,
                                        "error": f"sidecar unreachable: {getattr(e, 'reason', e)}"}))
        except Exception as e:
            self._send(200, json.dumps({"p_injection": None, "error": str(e)}))

    def log_message(self, *a):  # quiet
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8874)
    ap.add_argument("--sidecar", default="http://127.0.0.1:18902")
    a = ap.parse_args()
    Handler.sidecar = a.sidecar
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"[demo] serving injection demo on http://{a.host}:{a.port}/  -> sidecar {a.sidecar}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
