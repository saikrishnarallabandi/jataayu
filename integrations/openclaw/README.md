# OpenClaw adapter

This directory is the canonical OpenClaw adapter. Install the Jataayu Python package
in `python`'s environment, or configure `jataayuPath` to this repository's root.
The bridge invokes `python -m jataayu.runtime` with JSON on stdin. It never executes
request-generated Python or places content/credentials in process arguments.

The core and adapter must have the same product version and protocol schema.
The adapter snapshots the core fingerprint at activation and rejects subsequent
responses from changed code until the host is reloaded. `runtimeStatusPath` optionally
writes the loaded versions/fingerprints for deployment verification.

`effectBoundaryMode`, `toolReturnMode`, and `skillVetMode` accept enforce, shadow, off.
Unknown context is untrusted. External tool results retain provenance across turns,
independent of detector verdict. Guard errors block consequential operations in
enforce mode; outbound recovery errors replace the draft with a safe notice.

`policyFile` / `agent` supply capability and privacy policy. `toolEffects` supplies
explicit tool descriptors in the shared Python classifier. `trustedResultTools`
is an operator-owned exception list, empty by default. Only the host may supply
owner identity or source metadata; never pass model-generated metadata as trust.

Private fleet behavior can be supplied via an operator-configured `fleetExtensionPath`.
The extension may activate fleet hooks and provide `beforeOutbound`,
`classifierShadow`, and `alertWithheld`. It is trusted deployment code, not a path
accepted from a tool call. Project Ascent owns its fleet extension.
The former `record` extension hook is no longer called: metadata-only decision
receipts replace that payload-bearing logging path. Configure `decisionLogPath`
for logging; configuration changes require recreating the adapter on reload.

## Decision receipts (0.4.1)

Set `decisionLogPath` to a private JSONL path. Every Jataayu hook emits a metadata-only receipt with hashed session/run/call identifiers, a unique decision ID, code and policy fingerprints, mode, classification/provenance reasons, timing, and adapter disposition. `receiptTraffic` separates live, replay, and synthetic data. Missing identity and write failures are explicit. Payloads, detector excerpts, tokens, destinations, and action arguments are not emitted; legacy payload ledgers are superseded. Receipt IDs are pseudonymous correlation identifiers, not anonymization guarantees.

Run `python -m jataayu.observability PATH` for revision- and mode-separated event counts. These are neither unique-action counts nor a detector accuracy estimate. The adapter cannot attest that the host obeyed its return value; `host_acknowledgement` remains `unobserved`.

The installed OpenClaw runtime can persist results before asynchronous `after_tool_call` inspection finishes. Receipts expose pending/missing verdicts and late completions. Do not enable tool-return enforcement until a pre-delivery awaited boundary is verified: this release observes the race and preserves conservative enforcement behavior, it does not eliminate the host ordering limitation. Cached verdicts are scoped by session and tool-call ID to prevent cross-session collisions.

Tests: `node integrations/openclaw/receipts.test.js`; installed-host test: set `OPENCLAW_HOOK_RUNNER` to the installed hook-runner module and run `node integrations/openclaw/host-contract.test.js` in a separate process. It uses an empty registry and synthetic callbacks, not live actions. It verifies real dispatcher semantics, not the complete execution/delivery pipeline.

Review follow-up: an omitted `decisionLogPath` disables receipts silently; configured sink failures remain visible. Event and context tool-call IDs are both accepted for verdict correlation. Authorization fingerprints describe the normalized effective policy snapshot used by the decision, without a separate file read or stale mtime cache. Directory policies are supported.

## Awaited tool-result screening

When available, `registerAgentToolResultMiddleware` screens the complete JSON result, including structured details, before OpenClaw returns it to the model. The manifest declares the `openclaw` runtime contract. HIGH verdicts and runtime failures replace the entire result in enforce mode; shadow preserves it. Receipts use `hook=agent_tool_result`, `screening_path=awaited_middleware`, and an explicit screening state. A replacement receipt records the adapter response, not independent downstream acknowledgement.

Legacy after-tool and persistence hooks remain for paths without middleware coverage. These can produce additional observations for the same call; do not sum hook counts as unique tool calls. Legacy persistence still conservatively withholds missing or pending verdicts in enforce mode. The installed Codex native relay awaits middleware but discards replacements in its response; this adapter therefore does not register middleware for that runtime.

Run `node integrations/openclaw/middleware.test.js` for the adapter contract. Set `OPENCLAW_MIDDLEWARE_RUNNER` to the installed host tool-result-middleware module to exercise the host runner with synthetic results. This checks waiting, replacement, structured-output removal, failures, shadow/off behavior, and receipt privacy. It does not prove every live execution path invokes the middleware.
