from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(slots=True)
class ToolCallRecord:
    name: str
    arguments: object
    call_id: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ToolResultRecord:
    name: str
    result: object | None = None
    error: str | None = None
    call_id: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AgentTurnResult:
    assistant_message: str | None
    metadata: dict[str, object] = field(default_factory=dict)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    tool_results: list[ToolResultRecord] = field(default_factory=list)


class AgentAdapter(Protocol):
    agent_or_tools: object | None

    def run_turn(self, user_input: Any) -> AgentTurnResult | Any:
        ...
