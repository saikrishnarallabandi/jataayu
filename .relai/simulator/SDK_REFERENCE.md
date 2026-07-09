# RELAI Simulator SDK Reference

Use this reference instead of reading RELAI SDK source while scaffolding a
project simulator.

## Learning Environments

- Load a Python learning environment with `relai.load_learning_environment(path)`.
- Agent environments use `FixedInput` or `PersonaInput`.
- Component environments use `ComponentTarget(import_path="pkg.mod:func")`
  plus `FixedComponentInput` or `GeneratedComponentInput`.
- Every `RELAIEnvironment`, `CodeEvaluator`, and `LLMJudgeEvaluator` needs a
  short `description`.
- `ModelSpec(name="gpt-...", provider=None)` and `provider="openai"` use the
  default OpenAI Agents SDK model path.
- Non-OpenAI LLM judge, persona, and generated component-input models can use
  OpenAI-compatible endpoints with `ModelSpec(name="{provider-model}",
  provider="{provider}")`. Set `RELAI_MODEL_PROVIDER_<PROVIDER>_API_KEY` or
  `<PROVIDER>_API_KEY`, and set `RELAI_MODEL_PROVIDER_<PROVIDER>_BASE_URL`.
  RELAI uppercases the provider and converts non-alphanumeric characters to
  underscores for env var names.
- LiteLLM-backed models can use `ModelSpec(name="litellm/{provider/model}")` or
  `ModelSpec(name="{provider/model}", provider="litellm")` when
  `openai-agents[litellm]` is installed.

## Framework References

After identifying the project framework, read a matching file under
`.relai/simulator/frameworks/` before writing framework-specific adapter,
tool, mock, or component-target logic. Skip framework files that do not match
the project.
When framework-specific guidance conflicts with generic RELAI guidance, follow
the framework-specific guidance for framework mechanics such as target syntax,
input shape, tool wrapping, and mock application while preserving the generic
scenario and policy intent.

## Generic Runner Flow

The CLI-owned runner already handles this flow:

```python
environment = relai.load_learning_environment(learning_env_path)
with relai.TranscriptWriter.from_environment(environment, base_dir=project_root) as transcript:
    if isinstance(environment.target, relai.ComponentTarget):
        result = await relai.run_component_environment(environment, transcript)
    else:
        # The generic runner calls relai_simulator.adapter.build_agent_adapter().
        ...
    global_evaluators = relai.filter_global_evaluators_for_environment(
        relai.load_global_evaluators(project_root),
        environment,
        project_root=project_root,
    )
    evaluators = relai.combine_evaluators(
        environment.evaluators,
        global_evaluators,
    )
    await relai.run_evaluators(
        evaluators,
        result,
        transcript_writer=transcript,
        continue_on_error=True,
    )
    result = transcript.to_simulation_result(
        final_output=result.final_output,
        stop_reason=result.stop_reason,
        metadata=result.metadata,
    )
relai.write_simulation_result_json(result, result_json_path)
```

## Adapter Contract

Implement `.relai/simulator/src/relai_simulator/adapter.py`.

`build_agent_adapter()` must return an object with:

- `agent_or_tools`: framework agent, mutable tool list, or `None`.
- `run_turn(user_input)`: sync or async method. `user_input` is the
  JSON-serializable `FixedTurn.content` value. It may be a string, object, array,
  number, boolean, or null. String-only adapters remain valid for learning
  environments that use string turns.

`run_turn` may return:

- `AgentTurnResult(assistant_message=..., metadata={...})`
- a plain string
- a dict with `assistant_message` or `final_output`
- an object with `assistant_message` or `final_output`

For blocking sync agent calls, make `run_turn` async and use
`await asyncio.to_thread(sync_call, ...)`.

## Init Smoke Validation

Write `.relai/simulator/smoke_learning_env.py` as a minimal
`RELAIEnvironment` that runs one representative, project-valid fixed turn
through the generated adapter. Use the same public input shape that normal
learning environments should use. For agents that need structured input, put
that JSON-safe value directly in `FixedTurn(content=...)` rather than encoding
it as a JSON string.

## Mocks And Transcripts

- The generic runner enters `relai.MockApplication(environment.mocks)` before
  building the adapter.
- Import-path mocks support dotted attributes after the colon, such as
  `pkg.module:Class.method`, so multi-agent orchestrator subagent methods can
  be patched as component boundaries.
- If `agent_or_tools` is not `None`, the runner calls
  `mock_app.apply_tool_mocks(agent_or_tools)`.
- The runner records user messages, agent messages, adapter tool call/result
  records, observed RELAI mock calls, errors, run end, evaluator events, and
  result JSON.

## Dependency Edits

Do not add `relai` or other RELAI SDK dependencies. The CLI owns
SDK installation. If the project package must be importable, add the editable
project install inside the `BEGIN PROJECT DEPENDENCY INSTALL` section of
`.relai/simulator/install.sh`.

Preserve the CLI-generated virtualenv creation and dependency-manager flow.
Do not switch a uv seed to `python -m venv`, pip, Poetry, or another manager;
some supported hosts have uv available but do not have the system package
needed for `python -m venv`.
