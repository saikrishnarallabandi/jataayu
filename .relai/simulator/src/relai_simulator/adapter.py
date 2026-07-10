from __future__ import annotations

from collections.abc import Mapping

from agents import Runner

from jataayu_guard_agent.agent import create_guard_agent

from relai_simulator.adapter_contract import AgentAdapter, AgentTurnResult


def _assistant_input(user_input: object) -> list[dict[str, str]]:
    if not isinstance(user_input, str):
        raise TypeError(
            "The Jataayu simulator adapter expects each turn input to be a string "
            "containing the untrusted content to triage."
        )
    return [{"role": "user", "content": user_input}]


def _assistant_message_from_final_output(final_output: object) -> str | None:
    if final_output is None:
        return None
    if isinstance(final_output, str):
        return final_output.strip() or None
    if isinstance(final_output, Mapping):
        value = final_output.get("assistant_message", final_output.get("final_output"))
        return str(value).strip() if value is not None else None
    return str(final_output).strip() or None


class ProjectAgentAdapter:
    def __init__(self) -> None:
        self.agent_or_tools = create_guard_agent()

    async def run_turn(self, user_input: object) -> AgentTurnResult:
        result = await Runner.run(
            self.agent_or_tools,
            input=_assistant_input(user_input),
        )
        assistant_message = _assistant_message_from_final_output(
            getattr(result, "final_output", None)
        )
        if not assistant_message:
            assistant_message = ""
        return AgentTurnResult(
            assistant_message=assistant_message,
            metadata={"result_type": type(result).__name__},
        )


def build_agent_adapter() -> AgentAdapter:
    return ProjectAgentAdapter()
