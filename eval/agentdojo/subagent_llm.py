"""SubagentLLM — routes AgentDojo's agent-under-test turns to a Claude Code
subagent over a file-based RPC, instead of calling the Anthropic API.

Why: the only Anthropic credential in this environment is the session OAuth
token (short-lived, rate-limited, unusable for an unattended API sweep). Claude
Code subagents, however, have working Claude access through the harness. So we
run the "claude" AgentDojo column by having a subagent act as the model: the
python runner posts each turn's conversation + tool schemas to a request file
and blocks; the subagent reads it, decides the next action, and writes a
response file.

Protocol (files under $JATAAYU_RPC_DIR):
  req_<n>.json   {"n", "system", "messages":[...], "tools":[...]}   (runner -> subagent)
  resp_<n>.json  {"text": str|null, "tool_calls":[{"function","args"}]}  (subagent -> runner)
  DONE           written by the runner at exit so the subagent can stop.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Sequence

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime, EmptyEnv, Env
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.types import ChatAssistantMessage, ChatMessage, TextContentBlock


def _text_of(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    for block in content:
        if isinstance(block, dict):
            parts.append(str(block.get("content", "")))
        else:
            parts.append(str(getattr(block, "content", "")))
    return "\n".join(p for p in parts if p)


def _serialize_message(m: ChatMessage) -> dict:
    role = m.get("role")
    out: dict = {"role": role, "text": _text_of(m.get("content"))}
    if role == "assistant" and m.get("tool_calls"):
        out["tool_calls"] = [
            {"function": tc.function, "args": dict(tc.args), "id": tc.id}
            for tc in m["tool_calls"]
        ]
    if role == "tool":
        tc = m.get("tool_call")
        out["tool_name"] = tc.function if tc is not None else None
        out["tool_call_id"] = m.get("tool_call_id")
        if m.get("error"):
            out["error"] = m["error"]
    return out


def _serialize_tools(runtime: FunctionsRuntime) -> list[dict]:
    tools = []
    for f in runtime.functions.values():
        try:
            schema = f.parameters.model_json_schema()
        except Exception:
            schema = {}
        tools.append({"name": f.name, "description": f.description, "parameters": schema})
    return tools


class SubagentLLM(BasePipelineElement):
    """Agent-under-test backed by a Claude Code subagent over file RPC."""

    def __init__(self, rpc_dir: str, model_label: str = "claude-subagent",
                 poll_interval: float = 1.0, timeout: float = 3600.0) -> None:
        self.rpc_dir = Path(rpc_dir)
        self.rpc_dir.mkdir(parents=True, exist_ok=True)
        self.name = model_label
        self.poll_interval = poll_interval
        self.timeout = timeout

    def _next_index(self) -> int:
        # sequential across the whole run; count existing req files
        return len(list(self.rpc_dir.glob("req_*.json")))

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ):
        n = self._next_index()
        system = ""
        convo = []
        for m in messages:
            if m.get("role") == "system" and not convo:
                system = _text_of(m.get("content"))
            else:
                convo.append(_serialize_message(m))
        req = {"n": n, "system": system, "messages": convo, "tools": _serialize_tools(runtime)}
        req_path = self.rpc_dir / f"req_{n}.json"
        resp_path = self.rpc_dir / f"resp_{n}.json"
        tmp = req_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(req, default=str))
        tmp.rename(req_path)  # atomic publish

        waited = 0.0
        while not resp_path.exists():
            time.sleep(self.poll_interval)
            waited += self.poll_interval
            if waited > self.timeout:
                raise TimeoutError(f"subagent did not answer req_{n} within {self.timeout}s")
        resp = json.loads(resp_path.read_text())

        text = resp.get("text") or ""
        raw_calls = resp.get("tool_calls") or []
        tool_calls = None
        if raw_calls:
            tool_calls = [
                FunctionCall(function=c["function"], args=c.get("args", {}) or {},
                             id=c.get("id") or f"call_{n}_{i}")
                for i, c in enumerate(raw_calls)
            ]
        content = [TextContentBlock(type="text", content=text)] if text else None
        output = ChatAssistantMessage(role="assistant", content=content, tool_calls=tool_calls)
        messages = [*messages, output]
        return query, runtime, env, messages, extra_args
