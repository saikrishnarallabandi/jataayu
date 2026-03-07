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
    await gateway.start()

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
import os
from typing import Any, AsyncIterator, Optional
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
    ):
        self.upstream_url = upstream_url.rstrip("/")
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.block_threshold = block_threshold
        self.surface = surface
        self.enable_taint = enable_taint
        self.forward_headers = forward_headers or ["Authorization", "X-API-Key"]

        # Lazy imports — don't require aiohttp/fastapi unless gateway is used
        from jataayu.guards.inbound import InboundGuard
        self.guard = InboundGuard(use_llm=use_llm, llm_threshold=llm_threshold)

        if enable_taint:
            from jataayu.core.taint import TaintTracker
            self.taint_tracker: Optional[Any] = TaintTracker()
        else:
            self.taint_tracker = None

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

        context = {
            "tool_name": tool_name,
            "risk_score": effective_score,
            "blocked": blocked,
            "guard_result": result.to_dict(),
        }
        if taint_result:
            context["taint_result"] = taint_result.to_dict()

        if blocked:
            logger.warning(
                "MCP tool call BLOCKED: tool=%s risk=%.2f surface=%s patterns=%s",
                tool_name, effective_score, guard_surface, result.matched_patterns[:3],
            )
        elif not result.is_safe:
            logger.warning(
                "MCP tool call WARNING: tool=%s risk=%.2f explanation=%s",
                tool_name, effective_score, result.explanation,
            )

        return not blocked, context

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

                # Add security context header when there are warnings
                if not ctx.get("blocked") and ctx.get("risk_score", 0) > 0.3:
                    resp_headers["X-Jataayu-Warning"] = (
                        f"risk={ctx['risk_score']:.2f}"
                    )

                return resp.status, resp_headers, resp_body

    async def start_async_server(self) -> None:
        """Start the async HTTP proxy server using aiohttp."""
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

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.bind_host, self.bind_port)
        await site.start()

        logger.info(
            "Jataayu MCP Gateway listening on http://%s:%d → %s",
            self.bind_host, self.bind_port, self.upstream_url,
        )

    def start(self) -> None:
        """Start the gateway (blocking, runs asyncio event loop)."""
        import asyncio
        asyncio.run(self.start_async_server())

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
    )

    print(f"🛡️  Jataayu MCP Gateway")
    print(f"   Listening:  http://{args.host}:{args.port}")
    print(f"   Upstream:   {args.upstream}")
    print(f"   Threshold:  {args.block_threshold}")
    print(f"   Taint:      {'enabled' if args.enable_taint else 'disabled'}")
    print()

    gateway.start()


if __name__ == "__main__":
    main()
