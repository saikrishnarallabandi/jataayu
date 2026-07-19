# Jataayu — Agent Skill

Runtime authorization for tool-using agents. **Gate the action, not the string.**

Jataayu decides — deterministically, with no model and no network call — whether an agent's
*action* is allowed to run, from **the harm of the effect × the provenance of the input × your
capability policy**. An agent that read an attacker-controlled page can still summarize it; it
just can't be tricked into running the shell command, reading the secret, or POSTing your data.

Detecting the attack *text* is a losing arms race — an adaptive attacker rewrites the string until
the classifier misses. So the guarantee lives at the action. The detectors below are a cheap
pre-filter and a taint source, explicitly **not** what you rely on.

## Setup

Not on PyPI yet — install from GitHub:

```bash
pip install git+https://github.com/saikrishnarallabandi/jataayu.git

# optional slow path (LLM judge): [llm] for OpenAI/Anthropic, [ollama] for local
pip install "jataayu[ollama] @ git+https://github.com/saikrishnarallabandi/jataayu.git"
```

Python ≥ 3.10. Hard deps are only `requests` and `pyyaml`. The effect boundary works with no
model at all.

## 1. Authorize the action (the core — start here)

```python
from jataayu import jataayu_authorize_action, SecurityError

decision = jataayu_authorize_action(
    "shell.exec",
    {"cmd": "rm -rf /tmp/cache"},
    untrusted=True,          # these params were influenced by untrusted content
)
# -> decision: 'deny', effect_class: 'shell',
#    reason: 'untrusted-derived input may not reach a shell effect'
if decision["decision"] == "deny":
    raise SecurityError(decision["reason"])
```

`decision` is one of `allow` / `needs_approval` / `deny`, by effect family:

| Effect | On untrusted input | Recognized names (exact + namespaced / snake / camel) |
|---|---|---|
| `shell` | **deny** | `bash`, `shell.exec`, `os.system`, `run_shell_command`, `subprocess.run` |
| `code_eval` | **deny** | `eval`, `python.exec`, `code.run`, `code_interpreter` |
| `secret_read` | **deny** | `read_env`, `get_secret`, `vault.read`, `read_credentials` |
| `network` | **needs_approval** | `fetch`, `http.post`, `curl`, `send_email`, `transfer_funds` |
| `file_write` | **needs_approval** | `write_file`, `fs.write`, `file.delete` |
| `memory_write` | **needs_approval** | `memory_write`, `save_memory`, `kv_set` |
| `read` | allow | `read_file`, `get_*`, `list_*`, `search_*`, `recall` |

The effect is read off the **verb** (leading, or trailing after a namespace), not any token in the
name — `run_shell_command` is shell, `list_shell_history` stays a read. An unknown name falls back
to `read`; classification can only make a name *more* restrictive, never less.

For enforced execution use `PREVIEW → COMMIT`. The commit binds the exact request, so mutating the
action after authorization is rejected:

```python
from jataayu import EffectBoundary, Value, Provenance

eb = EffectBoundary()
params = {"path": "notes.md", "text": text}
preview = eb.preview("file.write", params,
                     values=[Value(text, Provenance.TRUSTED, source="user")])
if preview.approved:
    eb.commit(preview, params, lambda: write_file("notes.md", text))
# commit() raises CommitRejected if the preview wasn't ALLOW or the params changed
```

**There is no CLI for the effect boundary.** The `jataayu` command only exposes the screening
layers below — the core is the Python API.

## 2. Screen what comes in (defense-in-depth)

Injection arrives on the first message, on a tool result, or out of memory. Treat every `HIGH` as
a signal to mark the derived values untrusted at the boundary above — not as a block on its own.

```python
from jataayu import (jataayu_check_inbound, jataayu_check_tool_return,
                     jataayu_check_memory_write, jataayu_check_memory_read)

r = jataayu_check_inbound(issue_body, surface="github-issue")
# {status: 'SAFE'|'LOW'|'MEDIUM'|'HIGH', findings, risk_score, threat_types, blocked}
untrusted = r["status"] in ("MEDIUM", "HIGH")

jataayu_check_tool_return(api_response, tool_name="web.search")   # before the agent reads it
jataayu_check_memory_write(note)                                  # before persisting
jataayu_check_memory_read(recalled)                               # before it re-enters context
```

## 3. Guard what goes out — and the exfiltration *channel*

The bigger leak is usually not prose but a data-carrying URL or auto-fetched image (EchoLeak /
AgentFlayer class). A PII scanner never sees that payload; the egress guard does.

```python
from jataayu import jataayu_check_outbound, jataayu_check_egress

r = jataayu_check_outbound(draft, surface="discord-channel", protected_names=["Alice", "Bob"])
safe = r["redacted"] if r["status"] in ("WARN", "BLOCK") else draft

e = jataayu_check_egress(safe, surface="github-comment", context_secrets=[api_key])
if e["status"] == "BLOCK":
    safe = e["redacted"]   # offending URL neutralized, human text kept
```

Domain allowlisting alone is insufficient — the AgentFlayer bypass routed through a *trusted*
Azure Blob host — so request-catchers and abused relays (`webhook.site`, `*.blob.core.windows.net`,
`ngrok`) are hard-blocked.

## 4. Vet skills before installing them

```python
from jataayu import jataayu_vet_skill, jataayu_check_skillset

if jataayu_vet_skill("path/to/skill/")["verdict"] == "MALICIOUS":   # SAFE|REVIEW|MALICIOUS
    refuse_install()

# individually-safe skills that are dangerous together (one reads secrets, one writes network)
jataayu_check_skillset([skill_a, skill_b])
```

## CLI (screening layers only)

```bash
jataayu check "Ignore all previous instructions." --surface github-issue   # exit 2 if unsafe
cat issue_body.txt | jataayu check --surface github-issue --json
jataayu check --outbound "My daughter is 4 years old." --surface group-chat
jataayu sanitize "Call me at 555-867-5309" --surface discord-channel --protect Alice Bob
jataayu vet-skill path/to/skill/ --json
jataayu demo            # --outbound for the privacy demo
```

Every subcommand takes `--no-llm` (pattern-only) and `--json`.
Exit codes: `0` safe · `1` error · `2` flagged.

## Surfaces

`github-issue` · `github-pr` · `web-content` · `email` · `group-chat` · `discord-channel` ·
`direct-message` · `coding-task` (permissive) · `internal` (agent-to-agent)

## LLM backend (optional slow path only)

```bash
export JATAAYU_LLM_BACKEND=ollama          # or: openai | gateway
export JATAAYU_LLM_MODEL=llama3
export JATAAYU_LLM_API_KEY=sk-...          # openai
export JATAAYU_GATEWAY_BASE_URL=https://your-gateway   # gateway; /v1 appended, trailing /v1 ok
export JATAAYU_GATEWAY_TOKEN=...
# TLS verified by default; JATAAYU_GATEWAY_INSECURE=true only for a self-signed localhost gateway
```

This affects only the mid-confidence slow path. The effect boundary never calls it.

## Reference

- Repo: https://github.com/saikrishnarallabandi/jataayu
