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
The extension may activate fleet hooks and provide `record`, `beforeOutbound`,
`classifierShadow`, and `alertWithheld`. It is trusted deployment code, not a path
accepted from a tool call. Project Ascent owns its fleet extension.
