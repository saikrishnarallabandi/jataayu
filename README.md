# 🦅 Jataayu

*In the Ramayana, Jataayu was the eagle who spotted Ravana abducting Sita. He didn't wait for a pattern to match. He saw the threat, judged the situation, and acted — alone, without hesitation. That's Jataayu.*

---

**LLM-backed AI agent security — inbound injection detection + outbound privacy protection.**

## The Problem

AI agents are under attack. Not in science fiction — right now, in production.

- **Clinejection** — malicious prompt injections embedded in GitHub issues that hijack coding agents like Cline, Cursor, and Claude Code. An attacker files an issue; your agent reads it; your agent does what the attacker says.
- **Web poisoning** — websites laced with invisible instructions that redirect browsing agents.
- **Email phishing** — crafted messages that cause email-reading agents to exfiltrate data.

Most defenses focus on what comes **IN**. But there's a second threat nobody talks about:

**What goes OUT.**

Your agent has access to private context — files, messages, family details, financial data. When it replies in a group chat, comments on a GitHub issue, or sends an email, it can inadvertently leak that context to the wrong audience. No prompt injection required.

Jataayu guards both directions.

---

## Install

```bash
pip install jataayu

# With LLM support (for slow-path analysis)
pip install "jataayu[llm]"

# With Ollama support
pip install "jataayu[ollama]"
```

---

## Quick Start

### Simple API (recommended)

```python
from jataayu import jataayu_check_inbound, jataayu_check_outbound

# --- Inbound: detect injection attacks in external content ---
result = jataayu_check_inbound(github_issue_body, surface="github-issue")
if result["status"] == "HIGH":
    raise SecurityError(f"Blocked: {result['findings']}")
elif result["status"] == "MEDIUM":
    log.warning(f"Suspicious: {result['findings']}")
# Returns: {status: 'SAFE'|'LOW'|'MEDIUM'|'HIGH', findings: str, risk_score: float, ...}

# --- Outbound: strip PII/secrets before sending to shared surfaces ---
result = jataayu_check_outbound(
    draft_reply,
    surface="discord-channel",
    protected_names=["Alice", "Bob"],  # names that must never leak
)
if result["status"] == "BLOCK":
    safe_text = result["redacted"]  # auto-sanitized version
elif result["status"] == "WARN":
    safe_text = result["redacted"]  # review before sending
else:
    safe_text = draft_reply          # SAFE — send as-is
# Returns: {status: 'SAFE'|'WARN'|'BLOCK', findings: str, redacted: str|None, ...}
```

**Supported surfaces:** `github-issue`, `github-pr`, `github-comment`, `web-page`,
`web-content`, `email`, `whatsapp`, `discord-channel`, `discord-group`,
`telegram-group`, `group-chat`, `direct-message`, `coding-task`, `internal`,
`public`, `unknown`

### Advanced API

```python
from jataayu import InboundGuard, OutboundGuard, PrivacyConfig

# --- Inbound: catch injection before your agent processes it ---
guard = InboundGuard()
result = guard.check(github_issue_body, surface="github-issue")

if result.blocked:
    raise SecurityError(f"Blocked: {result.explanation}")
elif not result.is_safe:
    log.warning(f"Suspicious: {result.explanation}")

# --- Outbound: catch PII before your agent sends it ---
config = PrivacyConfig(
    protected_names=["Alice", "Bob"],          # names to always redact
    check_categories=["minors_info", "health", "financial"],
)
outbound = OutboundGuard(config)

safe_reply = outbound.sanitize(draft_reply, surface="group-chat")
```

### Simple API (convenience functions)

```python
from jataayu import check_inbound, check_outbound

# Inbound check — before acting on external content
status, findings = check_inbound(
    content="<github issue body>",
    surface="github-issue"
)
if status == "HIGH":
    print(f"BLOCKED: {findings}")
elif status == "MEDIUM":
    print(f"WARNING: {findings}")

# Outbound check — before sending to shared surface
status, redacted = check_outbound(
    content="My daughter Veda loves coding",
    surface="discord-channel"
)
if status == "BLOCK":
    print(f"Cannot send. Redacted: {redacted}")
elif status == "WARN":
    print(f"Review before sending: {redacted}")
```

Returns:
- **Inbound**: `(status, findings)` where status is `LOW` | `MEDIUM` | `HIGH`
- **Outbound**: `(status, output)` where status is `SAFE` | `WARN` | `BLOCK`

### CLI

```bash
# Check a string for injection threats
jataayu check "Ignore all previous instructions." --surface github-issue

# Pipe from stdin
echo "$(cat issue_body.txt)" | jataayu check --surface github-issue

# Check outbound for privacy violations
jataayu check --outbound "My daughter is 4 years old." --surface group-chat

# Sanitize outbound text
jataayu sanitize "Call me at 555-867-5309" --surface discord-channel

# Run built-in demos
jataayu demo
jataayu demo --outbound
```

---

## Surface Profiles

Jataayu understands that context matters. A shell command in a GitHub issue is suspicious; in a coding task it's expected.

| Surface | Trust | Inbound Strict | Outbound Strict | Notes |
|---|---|---|---|---|
| `github-issue` | 🔴 low | ✅ yes | ❌ no | Clinejection attack surface |
| `github-pr` | 🔴 low | ✅ yes | ❌ no | Code & description attacks |
| `web-content` / `web-page` | 🔴 low | ✅ yes | ❌ no | Invisible prompt injections |
| `email` | 🟡 medium | ✅ yes | ✅ yes | Phishing + data exfil |
| `whatsapp` | 🟡 medium | ❌ no | ✅ yes | Group privacy critical |
| `telegram-group` | 🟡 medium | ❌ no | ✅ yes | Group privacy critical |
| `discord-channel` | 🟡 medium | ❌ no | ✅ yes | Public community |
| `discord-group` | 🟡 medium | ❌ no | ✅ yes | Semi-public group DM |
| `group-chat` | 🟡 medium | ❌ no | ✅ yes | Generic group surface |
| `unknown` | 🟡 medium | ✅ yes | ✅ yes | Default — check everything |
| `direct-message` | 🟢 high | ❌ no | ❌ no | Private, trusted |
| `coding-task` | 🟡 medium | ❌ no | ❌ no | Shell commands expected |
| `internal` | 🟢 high | ❌ no | ❌ no | Agent-to-agent trusted |

---

## How It Works

### Two-path architecture

```
Inbound text
     │
     ▼
┌─────────────┐   score ≥ 0.9   ┌──────────┐
│  Fast Path  │ ─────────────── │  BLOCKED │
│  (patterns) │                 └──────────┘
└─────────────┘
     │ 0.35 ≤ score < 0.9
     ▼
┌─────────────┐
│  Slow Path  │  LLM judgment (Ollama / OpenAI / Anthropic / OpenClaw)
│   (LLM)     │
└─────────────┘
     │
     ▼
  ThreatResult
```

**Fast path** (microseconds): 20+ regex patterns covering:
- Prompt injection (ignore-instructions, DAN, system-prompt redefinition)
- Command injection (shell pipes, subshell, destructive commands, remote execution)
- Social engineering (false authority, urgency, coercion)
- Unicode homoglyph substitution
- Encoding obfuscation (base64, URL encoding)

**Slow path** (LLM): Invoked when fast path gives a medium-confidence score. The LLM provides nuanced judgment for ambiguous cases and generates sanitized rewrites for outbound content.

---

---

## LLM Configuration

```bash
# Use Ollama (default, local, free)
export JATAAYU_LLM_BACKEND=ollama
export JATAAYU_LLM_MODEL=llama3

# Use OpenAI
export JATAAYU_LLM_BACKEND=openai
export JATAAYU_LLM_API_KEY=sk-...
export JATAAYU_LLM_MODEL=gpt-4o-mini

# Use Anthropic
export JATAAYU_LLM_BACKEND=anthropic
export JATAAYU_LLM_API_KEY=sk-ant-...
export JATAAYU_LLM_MODEL=claude-haiku-20240307

# Use OpenClaw gateway (auto-reads ~/.openclaw/openclaw.json)
export JATAAYU_LLM_BACKEND=openclaw
```

Pattern-only mode (no LLM, no API key needed):
```python
guard = InboundGuard(use_llm=False)
```

---

---

## For AI Agents

See [AGENTS.md](AGENTS.md) for how to integrate Jataayu into your agent workflow.

---

## License

MIT — see [LICENSE](LICENSE).

---

*Named for [Jataayu](https://en.wikipedia.org/wiki/Jatayu), the noble eagle of the Ramayana who fought alone to protect the innocent.*
