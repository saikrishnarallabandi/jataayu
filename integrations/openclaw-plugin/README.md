# Jataayu OpenClaw plugin (enforced)

Wires Jataayu into the OpenClaw agent gateway (the "Judith pipeline") as an **enforced**
security layer — not an advisory tool the model can skip.

Source of truth lives here in the Jataayu repo. Deployed copies at
`~/.openclaw/plugins/jataayu/` should be regenerated from this directory via `./deploy.sh`.

## What it does
1. **Enforced inbound gate** (`registerHook("before_agent_run", ...)`): runs Jataayu's inbound
   injection screening on **every agent turn, before the agent processes the message**, and
   **blocks HIGH-confidence prompt injections**. Fires on real channel messages (WhatsApp /
   Discord / Telegram) via the gateway's `before_agent_run` path.
2. **Advisory tools** (`jataayu_check_inbound`, `jataayu_check_outbound`): kept as defense-in-depth
   for the agent to call explicitly.

## Safety
- **Fail-open**: the handler catches all errors and returns an explicit `{outcome:"pass"}`, and the
  Jataayu check times out at 6 s — well under OpenClaw's 15 s `before_agent_run` fail-closed timeout —
  so a guard fault can never block message delivery.
- `blockOnInboundHigh` (default true) toggles enforce vs warn/log-only.
- Observe it firing: `journalctl --user -u openclaw-gateway.service -f | grep jataayu-gate`

## Status / next
- Phase 1 (this): enforced **inbound** screening. Live.
- Phase 2 (next): the **effect boundary** via `registerNodeInvokePolicy` to gate device/tool
  actions by effect x provenance — the deterministic guarantee, not just detection.
