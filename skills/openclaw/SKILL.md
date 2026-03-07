# Jataayu — OpenClaw Skill

AI agent security: inbound injection detection + outbound privacy protection.

## Overview

Jataayu guards your AI agent against two threats:
1. **Inbound**: prompt injection, command injection, social engineering embedded in GitHub issues, web content, emails, and messages
2. **Outbound**: privacy/PII leakage before replies reach group chats, Discord channels, or public surfaces

## Setup

```bash
# Install the package
pip install jataayu

# Or from source
cd /path/to/jataayu
pip install -e .
```

## Usage in OpenClaw

### Check inbound content for injection threats

```
jataayu check "<text>" --surface github-issue
```

Or pipe from a file/variable:
```
echo "$ISSUE_BODY" | jataayu check --surface github-issue
```

### Check/sanitize outbound content for privacy violations

```
jataayu check --outbound "<draft reply>" --surface group-chat
jataayu sanitize "<draft reply>" --surface discord-channel
```

### Run the demo

```
jataayu demo
jataayu demo --outbound
```

## Python Integration

```python
from jataayu import InboundGuard, OutboundGuard, PrivacyConfig

# Inbound guard — pattern-only (no LLM required)
inbound = InboundGuard(use_llm=False)
result = inbound.check(text, surface="github-issue")
if result.blocked:
    raise SecurityError(result.explanation)

# Outbound guard — with protected names
config = PrivacyConfig(
    protected_names=["Alice", "Bob"],
    use_llm=True,  # uses JATAAYU_LLM_BACKEND env var
)
outbound = OutboundGuard(config)
safe_text = outbound.sanitize(draft, surface="group-chat")
```

## LLM Configuration

Set environment variables to configure the LLM backend:

```bash
# Use Ollama (local, default)
export JATAAYU_LLM_BACKEND=ollama
export JATAAYU_LLM_MODEL=llama3

# Use OpenAI
export JATAAYU_LLM_BACKEND=openai
export JATAAYU_LLM_API_KEY=sk-...

# Use OpenClaw gateway (auto-reads ~/.openclaw/openclaw.json)
export JATAAYU_LLM_BACKEND=openclaw
```

## Surface Names

Use these surface names for accurate threat profiling:

| Surface | Use when |
|---|---|
| `github-issue` | Processing GitHub issues |
| `github-pr` | Processing pull requests |
| `web-content` | Processing fetched web pages |
| `email` | Reading/sending email |
| `group-chat` | WhatsApp/Telegram groups |
| `discord-channel` | Discord channels |
| `direct-message` | Private DMs |
| `coding-task` | Coding/shell tasks (permissive) |
| `internal` | Agent-to-agent communication |

## Exit Codes (CLI)

- `0` — content is safe
- `1` — error (bad args, missing input)
- `2` — content is flagged (not safe) but not blocked

## Reference

- Repo: https://github.com/saikrishnarallabandi/jataayu
- AGENTS.md: guidance for AI agents using Jataayu
