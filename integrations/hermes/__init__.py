"""Hermes native action/result hooks over the shared Jataayu runtime.

Final-text transformation is not a wire-level streaming guarantee. Install only
with the coverage limitations in README.md understood; MCP tools remain advisory.
"""

import json
import logging
from collections import OrderedDict
from threading import RLock

from jataayu.runtime import dispatch

ADAPTER_VERSION = "0.4.3"
LOG = logging.getLogger("jataayu.hermes")

NOTICE = "This content was withheld by the security guard. Ask the operator to review it."


class Adapter:
    def __init__(self, config=None, runtime=dispatch):
        self.config = config or {}
        self.runtime = runtime
        self.origins = OrderedDict()
        self.lock = RLock()
        self.mode = self.config.get("effectBoundaryMode", "enforce")
        self.return_mode = self.config.get("toolReturnMode", "enforce")
        if self.mode not in ("enforce", "shadow", "off") or self.return_mode not in (
            "enforce",
            "shadow",
            "off",
        ):
            raise ValueError("Invalid Jataayu mode")
        self.health = self.call("health")

    def call(self, operation, **data):
        response = self.runtime(
            {"schema_version": 1, "config": self.config, "operation": operation, **data}
        )
        if (
            response.get("schema_version") != 1
            or response.get("core_version") != ADAPTER_VERSION
            or response.get("error")
            or not isinstance(response.get("result"), dict)
        ):
            raise ValueError("Invalid Jataayu runtime response")
        result = response["result"]
        if operation != "health":
            LOG.info(
                "operation=%s decision=%s",
                operation,
                result.get("decision", result.get("status", result.get("action"))),
            )
        return result

    def mark_external(self, key):
        if not key:
            return  # Missing identity is untrusted at authorization, never a bypass.
        with self.lock:
            self.origins[key] = ["external"]
            while len(self.origins) > 512:
                self.origins.popitem(last=False)

    def before_tool(self, tool_name, args=None, session_id="", task_id="", **kwargs):
        if self.mode == "off":
            return
        try:
            with self.lock:
                origins = self.origins.get(session_id or task_id, [])
            result = self.call("authorize", tool_name=tool_name, params=args or {}, origins=origins)
            decision = result.get("decision")
            if decision not in ("allow", "deny", "needs_approval"):
                raise ValueError("Invalid authorization decision")
            if self.mode == "shadow" or decision == "allow":
                return
            return {
                "action": "approve" if decision == "needs_approval" else "block",
                "message": result.get("reason") or NOTICE,
            }
        except Exception:
            if self.mode == "enforce":
                return {"action": "block", "message": "Jataayu authorization unavailable"}

    def transform_result(self, tool_name, result, session_id="", task_id="", **kwargs):
        self.mark_external(session_id or task_id)
        if self.return_mode == "off":
            return
        try:
            content = result if isinstance(result, str) else json.dumps(result)
            verdict = self.call("tool_return", tool_name=tool_name, content=content)
            if verdict.get("status") not in ("SAFE", "LOW", "MEDIUM", "HIGH"):
                raise ValueError("Invalid screening result")
            if self.return_mode == "enforce" and (
                verdict.get("blocked") or verdict["status"] == "HIGH"
            ):
                return json.dumps({"error": NOTICE})
        except Exception:
            if self.return_mode == "enforce":
                return json.dumps({"error": NOTICE})

    def transform_output(self, response_text, **kwargs):
        if self.config.get("enforceOutbound") is False:
            return
        try:
            result = self.call("recover", content=response_text, surface="public")
            if result.get("action") == "send" and isinstance(result.get("text"), str):
                return result["text"] or NOTICE
        except Exception:
            pass
        return NOTICE


def register(ctx):
    from hermes_cli.config import load_config

    config = load_config().get("plugins", {}).get("entries", {}).get(ctx.manifest.name, {})
    adapter = Adapter(config.get("config", config))
    ctx.register_hook("pre_tool_call", adapter.before_tool)
    ctx.register_hook("transform_tool_result", adapter.transform_result)
    ctx.register_hook("transform_llm_output", adapter.transform_output)
