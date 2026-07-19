"""
Jataayu MCP Gateway
===================
Streamable HTTP proxy that intercepts MCP tool calls and runs InboundGuard
checks on parameters before forwarding to the upstream MCP server.

Architecture:
  Client → JataayuMCPGateway → InboundGuard.check() → upstream MCP server

The gateway:
  1. Receives MCP JSON-RPC requests (tools/call, tools/list, etc.)
  2. For tools/call: runs InboundGuard on all parameter values
  3. If threat detected: returns a JSON-RPC error (blocked) or warning
  4. If safe: forwards to the upstream MCP server and streams back the response

This implements a before_tool_call hook — a security layer that sits between
the agent and the MCP server without requiring changes to either.

Usage:
    # Start the gateway
    gateway = JataayuMCPGateway(
        upstream_url="http://localhost:8000",  # your MCP server
        bind_port=8001,
        use_llm=False,  # fast-path only in production
    )
    gateway.start()  # blocks; or `await gateway.serve_forever()` inside a loop

    # Or as a drop-in via CLI:
    python -m jataayu.integrations.mcp_gateway \
        --upstream http://localhost:8000 \
        --port 8001

Security:
    - All tool call parameters are scanned before forwarding
    - Blocked requests return JSON-RPC error code -32600 (Invalid Request)
    - Suspicious (non-blocked) requests return a warning header X-Jataayu-Warning
    - Taint tracking can be enabled to track untrusted data flows
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Any, Optional
from urllib.parse import urljoin

logger = logging.getLogger("jataayu.mcp_gateway")


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _jsonrpc_error(id: Any, code: int, message: str, data: Optional[dict] = None) -> dict:
    resp = {
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    }
    if data:
        resp["error"]["data"] = data
    return resp


def _jsonrpc_ok(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


# ---------------------------------------------------------------------------
# MCP Gateway core
# ---------------------------------------------------------------------------

class JataayuMCPGateway:
    """
    Drop-in MCP proxy with InboundGuard before_tool_call hook.

    Intercepts MCP JSON-RPC requests and scans tool call parameters
    for injection attacks before forwarding to the upstream server.

    Supports:
    - Streamable HTTP (SSE) — MCP 2025-03-26 spec
    - Traditional request/response JSON-RPC
    - Taint tracking for Clinejection flow analysis

    Args:
        upstream_url: Base URL of the upstream MCP server.
        bind_host: Host to bind the gateway to. Default: localhost.
        bind_port: Port to bind the gateway to. Default: 8765.
        use_llm: Whether to use LLM slow path in InboundGuard. Default: False.
        llm_threshold: Risk score threshold for LLM escalation. Default: 0.5.
        block_threshold: Risk score above which to block the request. Default: 0.7.
        surface: Surface name for InboundGuard. Default: "mcp-tool-call".
        enable_taint: Enable taint tracking integration. Default: False.
        forward_headers: HTTP headers to forward from client to upstream.
        mode: "enforce" (default, block) or "observe" (measure only — nothing is blocked,
            but every would-be block is reported on the context, the X-Jataayu-Would-Block
            header and the decision sink).
    """

    JSONRPC_SECURITY_ERROR = -32001  # Custom error code for security blocks

    def __init__(
        self,
        upstream_url: str,
        bind_host: str = "127.0.0.1",
        bind_port: int = 8765,
        use_llm: bool = False,
        llm_threshold: float = 0.5,
        block_threshold: float = 0.7,
        surface: str = "mcp-tool-call",
        enable_taint: bool = False,
        forward_headers: Optional[list[str]] = None,
        inspect_returns: bool = True,
        return_surface: str = "tool-return",
        mode: str = "enforce",
    ):
        if mode not in ("enforce", "observe"):
            raise ValueError(f"invalid mode {mode!r} — expected 'enforce' or 'observe'")
        self.mode = mode
        if mode == "observe":
            # A security proxy silently not blocking is the worst failure here, so say so
            # at startup as well as per-decision.
            logger.warning("Jataayu MCP Gateway in OBSERVE MODE — nothing will be blocked")
        self.upstream_url = upstream_url.rstrip("/")
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.block_threshold = block_threshold
        self.surface = surface
        self.enable_taint = enable_taint
        self.forward_headers = forward_headers or ["Authorization", "X-API-Key"]
        # after_tool_call: scan tool RETURN values before the agent consumes them.
        # The 2026 literature (DeepTrap) shows the execution context — not just the
        # prompt and call params — is the attack surface: a tool can return a
        # malicious page / injected instructions that the agent then acts on.
        self.inspect_returns = inspect_returns
        self.return_surface = return_surface

        # Realized ports of the live listeners, one entry per run (see the
        # bound_port property). Distinct from bind_port, which stays the caller's
        # configuration (0 = "pick an ephemeral port", and it must keep meaning
        # that on restart).
        self._bound_ports: list[int] = []

        # stop() may land before serve_forever() has registered its waiter — the
        # bound_port readiness signal is published earlier — so stop requests are
        # counted, not just signalled: a run samples the count before binding and
        # exits immediately if it changed by the time it registers. A counter
        # rather than a flag so concurrent runs can't clear each other's request.
        self._lock = threading.Lock()
        self._stop_epoch = 0
        self._waiters: list[tuple[Any, Any]] = []

        # Lazy imports — don't require aiohttp/fastapi unless gateway is used
        from jataayu.guards.inbound import InboundGuard
        self.guard = InboundGuard(use_llm=use_llm, llm_threshold=llm_threshold)

        if enable_taint:
            from jataayu.core.taint import TaintTracker
            self.taint_tracker: Optional[Any] = TaintTracker()
        else:
            self.taint_tracker = None

    @property
    def bound_port(self) -> Optional[int]:
        """
        The port the kernel actually gave us — the readiness signal — or None
        while nothing is bound. With concurrent runs on one gateway this is the
        most recently bound *live* listener: a run retires only its own port when
        its runner is cleaned up, so runs can't clear each other's.
        """
        with self._lock:
            return self._bound_ports[-1] if self._bound_ports else None

    # Sink risk scores — used even without taint to assess inherent danger of tools
    _SINK_BASE_SCORES: dict[str, float] = {
        "bash": 0.60, "shell": 0.60, "exec": 0.60, "execute": 0.60,
        "run": 0.55, "run_command": 0.60, "execute_command": 0.60,
        "run_terminal_cmd": 0.60, "terminal": 0.55, "sh": 0.60,
        "cmd": 0.55, "powershell": 0.60, "subprocess": 0.60,
        "computer_use_bash": 0.60, "computer_use_shell": 0.60,
    }

    def before_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        taint_ids: Optional[list[str]] = None,
    ) -> tuple[bool, dict]:
        """
        Run InboundGuard on tool call parameters.

        Args:
            tool_name: The MCP tool being called.
            params: Tool call parameters.
            taint_ids: Optional taint IDs from the taint tracker.

        Returns:
            (allowed, context) — if allowed=False, the request should be blocked.
            context contains the ThreatResult dict and any warnings.
        """
        # Flatten params to text for InboundGuard
        param_text = self._params_to_text(params)

        # Run InboundGuard on parameter text
        guard_surface = self.surface
        result = self.guard.check(param_text, surface=guard_surface)

        # Incorporate inherent sink risk of the tool name
        tool_sink_score = self._SINK_BASE_SCORES.get(tool_name.lower(), 0.0)

        # Also check via taint tracker if enabled
        taint_result = None
        if self.taint_tracker and taint_ids:
            taint_result = self.taint_tracker.check_tool_call(
                tool_name=tool_name,
                params=params,
                taint_ids=taint_ids,
            )

        # Determine if we should block
        effective_score = max(result.risk_score, tool_sink_score)
        if taint_result and taint_result.risk_score > effective_score:
            effective_score = taint_result.risk_score

        blocked = effective_score >= self.block_threshold
        enforced = blocked and self.mode == "enforce"

        context = {
            "tool_name": tool_name,
            "risk_score": effective_score,
            "blocked": enforced,
            "would_block": blocked,
            "mode": self.mode,
            "guard_result": result.to_dict(),
        }
        if taint_result:
            context["taint_result"] = taint_result.to_dict()

        if blocked:
            logger.warning(
                "MCP tool call %s: tool=%s risk=%.2f surface=%s patterns=%s",
                "BLOCKED" if enforced else "WOULD BLOCK (observe mode)",
                tool_name, effective_score, guard_surface, result.matched_patterns[:3],
            )
        elif not result.is_safe:
            logger.warning(
                "MCP tool call WARNING: tool=%s risk=%.2f explanation=%s",
                tool_name, effective_score, result.explanation,
            )

        self._emit(tool_name, "call", effective_score, enforced, blocked, result.explanation)
        return not enforced, context

    def after_tool_call(
        self,
        tool_name: str,
        result: Any,
        taint_ids: Optional[list[str]] = None,
    ) -> tuple[bool, dict]:
        """
        Run InboundGuard on a tool's RETURN value before the agent consumes it.

        This is the dual of before_tool_call: rather than scanning the parameters
        going *into* a tool, it scans what comes *out*. Tool returns are
        attacker-influenceable (a web-fetch tool can return a page containing
        "ignore previous instructions"), so they are treated as untrusted inbound
        content on the `tool-return` surface.

        Args:
            tool_name: The MCP tool that produced this result.
            result: The tool result — raw MCP result dict, list, or text.
            taint_ids: Optional taint IDs (the return is itself a new taint source).

        Returns:
            (safe, context) — if safe=False, the return should be withheld from
            the agent (it carries an injection payload).
        """
        result_text = self._extract_result_text(result)

        if not result_text.strip():
            return True, {"tool_name": tool_name, "risk_score": 0.0, "blocked": False}

        guard_result = self.guard.check(result_text, surface=self.return_surface)
        blocked = guard_result.risk_score >= self.block_threshold
        enforced = blocked and self.mode == "enforce"

        context = {
            "tool_name": tool_name,
            "risk_score": guard_result.risk_score,
            "blocked": enforced,
            "would_block": blocked,
            "mode": self.mode,
            "direction": "return",
            "guard_result": guard_result.to_dict(),
        }

        if blocked:
            logger.warning(
                "MCP tool RETURN %s: tool=%s risk=%.2f surface=%s patterns=%s",
                "BLOCKED" if enforced else "WOULD BLOCK (observe mode)",
                tool_name, guard_result.risk_score, self.return_surface,
                guard_result.matched_patterns[:3],
            )
        elif not guard_result.is_safe:
            logger.warning(
                "MCP tool RETURN WARNING: tool=%s risk=%.2f explanation=%s",
                tool_name, guard_result.risk_score, guard_result.explanation,
            )

        self._emit(tool_name, "return", guard_result.risk_score, enforced, blocked,
                   guard_result.explanation)
        return not enforced, context

    def _emit(self, tool_name: str, direction: str, risk: float,
              enforced: bool, would_block: bool, reason: str) -> None:
        """Report one gateway decision to the sink, alongside effect-boundary decisions."""
        from jataayu.core.audit import emit_decision

        emit_decision({
            "rail_type": "inbound",
            "tool_name": tool_name,
            "direction": direction,
            "risk_score": risk,
            "decision": "deny" if enforced else "allow",
            "would_decision": "deny" if would_block else "allow",
            "tripwire_triggered": would_block,
            "mode": self.mode,
            "reason": reason,
        })

    def inspect_tool_response(
        self,
        tool_name: str,
        response_body: bytes,
    ) -> tuple[bytes, dict]:
        """
        Inspect a JSON-RPC tool-call response body and, if the tool return carries
        an injection payload, replace it with a safety notice so the agent never
        consumes the payload.

        Args:
            tool_name: The tool that produced the response.
            response_body: Raw JSON-RPC response bytes from the upstream server.

        Returns:
            (possibly_modified_body, context) — body is unchanged when the return
            is safe; replaced with a JSON-RPC result carrying a block notice when not.
        """
        try:
            resp = json.loads(response_body.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not JSON we can inspect (e.g. SSE chunk) — pass through untouched.
            return response_body, {"tool_name": tool_name, "inspected": False}

        result = resp.get("result")
        if result is None:
            return response_body, {"tool_name": tool_name, "inspected": False}

        safe, ctx = self.after_tool_call(tool_name, result)
        ctx["inspected"] = True

        if safe:
            return response_body, ctx

        # Withhold the malicious payload: replace the result content with a notice.
        risk = ctx.get("risk_score", 0.0)
        notice = {
            "content": [{
                "type": "text",
                "text": (
                    f"[Jataayu blocked this tool return: it carried a suspected "
                    f"injection payload (risk={risk:.2f}). The original content was "
                    f"withheld from the agent.]"
                ),
            }],
            "isError": True,
            "_jataayu_blocked": True,
        }
        resp["result"] = notice
        return json.dumps(resp).encode(), ctx

    def handle_jsonrpc(self, request_body: str) -> tuple[str, bool, dict]:
        """
        Process a single JSON-RPC request (synchronous).

        For tools/call requests, runs before_tool_call hook.
        For all other methods, passes through.

        Args:
            request_body: Raw JSON string of the request.

        Returns:
            (response_or_error_json, should_forward, security_context)
        """
        try:
            req = json.loads(request_body)
        except json.JSONDecodeError as e:
            err = _jsonrpc_error(None, -32700, f"Parse error: {e}")
            return json.dumps(err), False, {}

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        # Only inspect tool calls
        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_params = params.get("arguments", params.get("params", {}))

            # Get any active taint IDs from params metadata
            taint_ids = params.get("_jataayu_taint_ids")

            allowed, ctx = self.before_tool_call(tool_name, tool_params, taint_ids)

            if not allowed:
                risk = ctx.get("risk_score", 0)
                guard_result = ctx.get("guard_result", {})
                explanation = guard_result.get("explanation", "Security check failed")
                matched = guard_result.get("matched_patterns", [])

                error_resp = _jsonrpc_error(
                    req_id,
                    self.JSONRPC_SECURITY_ERROR,
                    f"Tool call blocked by Jataayu security guard (risk={risk:.2f}): {explanation}",
                    data={
                        "tool": tool_name,
                        "risk_score": risk,
                        "matched_patterns": matched[:5],
                        "jataayu_blocked": True,
                    },
                )
                return json.dumps(error_resp), False, ctx

            # Request is safe to forward; include security context in metadata
            return request_body, True, ctx

        # Non-tool-call methods pass through without inspection
        return request_body, True, {}

    async def proxy_request_async(
        self,
        method: str,
        path: str,
        headers: dict,
        body: bytes,
    ) -> tuple[int, dict, bytes]:
        """
        Async HTTP proxy: intercept, check, forward to upstream.

        Returns:
            (status_code, response_headers, response_body)
        """
        try:
            import aiohttp
        except ImportError:
            raise RuntimeError(
                "aiohttp is required for async proxy mode. "
                "Install with: pip install aiohttp"
            )

        # Parse and check the request body
        body_str = body.decode("utf-8", errors="replace")
        modified_body, should_forward, ctx = self.handle_jsonrpc(body_str)

        if not should_forward:
            # Return the error response directly — don't forward to upstream
            return (
                200,  # JSON-RPC errors use HTTP 200 with error in body
                {"Content-Type": "application/json"},
                modified_body.encode(),
            )

        # Forward to upstream
        upstream_path = urljoin(self.upstream_url + "/", path.lstrip("/"))
        forward_hdrs = {
            k: v for k, v in headers.items()
            if k in self.forward_headers or k.lower().startswith("content-")
        }

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=method,
                url=upstream_path,
                headers=forward_hdrs,
                data=modified_body.encode(),
            ) as resp:
                resp_body = await resp.read()
                resp_headers = dict(resp.headers)

                # In observe mode the request was forwarded despite tripping the threshold —
                # say so on the wire, so the caller can measure without enforcing.
                if ctx.get("would_block") and not ctx.get("blocked"):
                    resp_headers["X-Jataayu-Would-Block"] = "true"

                # Add security context header when there are warnings
                if not ctx.get("blocked") and ctx.get("risk_score", 0) > 0.3:
                    resp_headers["X-Jataayu-Warning"] = (
                        f"risk={ctx['risk_score']:.2f}"
                    )

                # after_tool_call: scan the tool RETURN before it reaches the agent.
                # Only for tool-call responses (ctx carries tool_name) and when the
                # upstream returned an inspectable JSON body (not an SSE stream).
                tool_name = ctx.get("tool_name")
                content_type = resp_headers.get("Content-Type", "")
                if (
                    self.inspect_returns
                    and tool_name
                    and "text/event-stream" not in content_type
                ):
                    resp_body, ret_ctx = self.inspect_tool_response(tool_name, resp_body)
                    if ret_ctx.get("blocked"):
                        resp_headers["X-Jataayu-Return-Blocked"] = "true"
                        # Body changed length — let the client/aiohttp recompute.
                        resp_headers.pop("Content-Length", None)
                    elif ret_ctx.get("risk_score", 0) > 0.3:
                        resp_headers["X-Jataayu-Return-Warning"] = (
                            f"risk={ret_ctx['risk_score']:.2f}"
                        )

                return resp.status, resp_headers, resp_body

    async def start_async_server(self) -> Any:
        """
        Bind and start the async HTTP proxy server using aiohttp.

        Non-blocking: returns as soon as the listener is bound, so callers that
        manage their own event loop can start the gateway alongside other work.
        Use `start()` for a blocking server, or await `serve_forever()` from an
        existing loop.

        Returns:
            The aiohttp AppRunner — the caller owns it and must `await
            runner.cleanup()` to release the socket.
        """
        try:
            from aiohttp import web
        except ImportError:
            raise RuntimeError(
                "aiohttp is required for the MCP Gateway server. "
                "Install with: pip install aiohttp"
            )

        gateway = self

        async def handle_request(request: web.Request) -> web.StreamResponse:
            body = await request.read()
            status, headers, resp_body = await gateway.proxy_request_async(
                method=request.method,
                path=request.path,
                headers=dict(request.headers),
                body=body,
            )

            # Check if upstream returns SSE
            content_type = headers.get("Content-Type", "")
            if "text/event-stream" in content_type:
                response = web.StreamResponse(status=status, headers=headers)
                await response.prepare(request)
                await response.write(resp_body)
                return response

            return web.Response(status=status, headers=headers, body=resp_body)

        app = web.Application()
        app.router.add_route("*", "/{path_info:.*}", handle_request)

        class _GatewayRunner(web.AppRunner):
            # The realized port belongs to this listener, not to the gateway:
            # releasing the socket is what retires the port, whether that is
            # serve_forever or a caller cleaning up the runner it was handed.
            _jataayu_port: Optional[int] = None

            async def cleanup(self) -> None:
                with gateway._lock:
                    port = self._jataayu_port
                    self._jataayu_port = None
                    if port is not None:
                        gateway._bound_ports.remove(port)
                await super().cleanup()

        runner = _GatewayRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, self.bind_host, self.bind_port)
            await site.start()
            # bind_port may be 0 (ephemeral); the kernel's choice is published on
            # bound_port so the configured value survives for the next bind.
            port = runner.addresses[0][1]
        except BaseException:
            await runner.cleanup()
            raise

        with self._lock:
            self._bound_ports.append(port)
            runner._jataayu_port = port

        logger.info(
            "Jataayu MCP Gateway listening on http://%s:%d → %s",
            self.bind_host, port, self.upstream_url,
        )
        return runner

    async def serve_forever(self) -> None:
        """
        Start the server and serve until `stop()` is called or the task is
        cancelled. Releases the listening socket on the way out.
        """
        import asyncio

        with self._lock:
            # Stops requested before this point belong to a previous run.
            epoch = self._stop_epoch

        runner = await self.start_async_server()
        waiter = (asyncio.get_running_loop(), asyncio.Event())
        with self._lock:
            self._waiters.append(waiter)
            stop_already_requested = self._stop_epoch != epoch
        if stop_already_requested:
            waiter[1].set()
        try:
            await waiter[1].wait()
        finally:
            with self._lock:
                self._waiters.remove(waiter)
            await runner.cleanup()

    def stop(self) -> None:
        """
        Ask every running `start()` / `serve_forever()` on this gateway to shut
        down. Thread-safe, and safe to call before the server is up — the request
        is latched, so a serve_forever() still binding will exit as soon as it is.
        """
        with self._lock:
            self._stop_epoch += 1
            waiters = list(self._waiters)
        for loop, shutdown in waiters:
            try:
                loop.call_soon_threadsafe(shutdown.set)
            except RuntimeError:
                pass  # loop already closed; that run is over anyway

    def start(self) -> None:
        """Start the gateway (blocking, runs asyncio event loop)."""
        import asyncio
        try:
            asyncio.run(self.serve_forever())
        except KeyboardInterrupt:
            logger.info("Jataayu MCP Gateway shutting down")

    @staticmethod
    def _params_to_text(params: Any, depth: int = 0) -> str:
        """Recursively flatten params dict/list to a single string."""
        if depth > 5:
            return str(params)[:500]
        if isinstance(params, str):
            return params
        if isinstance(params, (list, tuple)):
            return " ".join(
                JataayuMCPGateway._params_to_text(p, depth + 1)
                for p in params
            )
        if isinstance(params, dict):
            return " ".join(
                JataayuMCPGateway._params_to_text(v, depth + 1)
                for v in params.values()
            )
        return str(params)

    @staticmethod
    def _extract_result_text(result: Any) -> str:
        """
        Flatten an MCP tool result to text for return-value scanning.

        MCP tool results are typically {"content": [{"type": "text", "text": ...}]}.
        Falls back to recursively flattening any dict/list/scalar.
        """
        if isinstance(result, dict) and isinstance(result.get("content"), list):
            parts = []
            for item in result["content"]:
                if isinstance(item, dict) and "text" in item:
                    parts.append(str(item["text"]))
                else:
                    parts.append(JataayuMCPGateway._params_to_text(item))
            return " ".join(parts)
        return JataayuMCPGateway._params_to_text(result)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Jataayu MCP Gateway — security proxy for MCP servers",
    )
    parser.add_argument("--upstream", required=True, help="Upstream MCP server URL")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM slow path")
    parser.add_argument("--block-threshold", type=float, default=0.7,
                        help="Risk score threshold to block (default: 0.7)")
    parser.add_argument("--surface", default="mcp-tool-call", help="Surface name for guard")
    parser.add_argument("--enable-taint", action="store_true", help="Enable taint tracking")
    parser.add_argument("--observe", action="store_true",
                        help="Observe mode: report what WOULD be blocked, block nothing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    gateway = JataayuMCPGateway(
        upstream_url=args.upstream,
        bind_host=args.host,
        bind_port=args.port,
        use_llm=args.use_llm,
        block_threshold=args.block_threshold,
        surface=args.surface,
        enable_taint=args.enable_taint,
        mode="observe" if args.observe else "enforce",
    )

    print("🛡️  Jataayu MCP Gateway")
    print(f"   Listening:  http://{args.host}:{args.port}")
    print(f"   Upstream:   {args.upstream}")
    print(f"   Threshold:  {args.block_threshold}")
    print(f"   Taint:      {'enabled' if args.enable_taint else 'disabled'}")
    print(f"   Mode:       {gateway.mode}")
    if args.observe:
        print("   *** OBSERVE MODE — nothing will be blocked ***")
    print()

    gateway.start()


if __name__ == "__main__":
    main()
