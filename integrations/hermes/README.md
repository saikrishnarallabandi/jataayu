# Hermes adapter

Install the Jataayu Python package in the Hermes interpreter and link this directory
into the profile's plugins directory. Add `jataayu` to `plugins.enabled` and put
settings in `plugins.entries.jataayu`. The adapter reads no OpenClaw configuration.
Private policy should be supplied using `policyFile` and optional `agent`.

The adapter implements native `pre_tool_call`, `transform_tool_result`, and
`transform_llm_output` hooks. Unknown provenance is untrusted. Error paths block in
enforce mode. `effectBoundaryMode` and `toolReturnMode` accept enforce, shadow, off.
Shadow logs/measurement should be integrated before promotion to enforce.

Coverage: final-text transformation happens after the model turn. It does not cover
streamed tokens already delivered, direct platform sends outside the tool executor,
or a higher-priority transform replacing the result first. This adapter must not be
advertised as a complete outbound wire guard. Verify those host paths or disable
streaming for a deployment requiring that guarantee.
