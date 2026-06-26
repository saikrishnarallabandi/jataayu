"""
Jataayu surface profiles.

Each surface profile defines how strictly Jataayu should treat
inbound content and outbound responses for a given communication channel.

Trust levels:
  low    — treat everything as potentially hostile (public internet, untrusted contributors)
  medium — semi-trusted; apply standard checks
  high   — trusted context; relax most restrictions

inbound_strict: True → lower risk threshold for blocking, full pattern scan + LLM
outbound_strict: True → always run outbound PII/privacy guard before sending
"""

SURFACE_PROFILES: dict[str, dict] = {
    "github-issue": {
        "trust_level": "low",
        "description": "GitHub issue from a potentially anonymous contributor",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.2,
        "watch_for": ["prompt_injection", "command_injection", "social_engineering"],
        "notes": "Clinejection attacks arrive here. Treat all issue bodies as hostile until proven safe.",
    },
    "github-pr": {
        "trust_level": "low",
        "description": "GitHub pull request — code review context",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.2,
        "watch_for": ["prompt_injection", "command_injection", "encoding_obfuscation"],
        "notes": "PR descriptions, comments, and code changes can all carry injections.",
    },
    "github-comment": {
        "trust_level": "low",
        "description": "GitHub issue or PR comment",
        "inbound_strict": True,
        "outbound_strict": True,
        "risk_multiplier": 1.15,
        "watch_for": ["prompt_injection", "social_engineering"],
        "notes": "Comments from unknown users on public repos.",
    },
    "web-content": {
        "trust_level": "low",
        "description": "Content fetched from the public web (web scraping, browsing)",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.1,
        "watch_for": ["prompt_injection", "unicode_bypass", "encoding_obfuscation"],
        "notes": "Web pages can contain invisible or encoded injection payloads.",
    },
    "group-chat": {
        "trust_level": "medium",
        "description": "Group messaging surface (WhatsApp group, Telegram group, etc.)",
        "inbound_strict": False,
        "outbound_strict": True,
        "risk_multiplier": 1.0,
        "watch_for": ["social_engineering", "pii_leakage"],
        "notes": "Outbound privacy critical — group messages are seen by many people.",
    },
    "discord-channel": {
        "trust_level": "medium",
        "description": "Discord channel (semi-public, community space)",
        "inbound_strict": False,
        "outbound_strict": True,
        "risk_multiplier": 1.0,
        "watch_for": ["social_engineering", "pii_leakage", "prompt_injection"],
        "notes": "Public Discord channels are equivalent to group-chat for outbound privacy.",
    },
    "email": {
        "trust_level": "medium",
        "description": "Email (inbound from external sender or outbound to external recipient)",
        "inbound_strict": True,
        "outbound_strict": True,
        "risk_multiplier": 1.15,
        "watch_for": ["social_engineering", "pii_leakage", "prompt_injection"],
        "notes": "Phishing arrives via email. Outbound email also carries privacy risk.",
    },
    "direct-message": {
        "trust_level": "high",
        "description": "Direct/private message to a known, trusted individual",
        "inbound_strict": False,
        "outbound_strict": False,
        "risk_multiplier": 0.8,
        "watch_for": [],
        "notes": "Private DMs to confirmed contacts. Relaxed but not disabled.",
    },
    "coding-task": {
        "trust_level": "medium",
        "description": "Coding agent task — shell commands and code execution are expected",
        "inbound_strict": False,
        "outbound_strict": False,
        "risk_multiplier": 0.7,
        "watch_for": ["social_engineering"],
        "notes": "Shell patterns are legitimate here; lower risk multiplier avoids false positives.",
    },
    "internal": {
        "trust_level": "high",
        "description": "Internal system message or agent-to-agent communication",
        "inbound_strict": False,
        "outbound_strict": False,
        "risk_multiplier": 0.5,
        "watch_for": [],
        "notes": "Trusted internal channel. Minimal scrutiny.",
    },
    "whatsapp": {
        "trust_level": "medium",
        "description": "WhatsApp message (individual or group)",
        "inbound_strict": False,
        "outbound_strict": True,
        "risk_multiplier": 1.1,
        "watch_for": ["social_engineering", "pii_leakage"],
        "notes": "Outbound privacy critical in group chats. Individual chats are moderate risk.",
    },
    "telegram-group": {
        "trust_level": "medium",
        "description": "Telegram group chat — messages visible to all group members",
        "inbound_strict": False,
        "outbound_strict": True,
        "risk_multiplier": 1.1,
        "watch_for": ["social_engineering", "pii_leakage"],
        "notes": "Treat like group-chat for outbound privacy.",
    },
    "discord-group": {
        "trust_level": "medium",
        "description": "Discord group DM or server channel",
        "inbound_strict": False,
        "outbound_strict": True,
        "risk_multiplier": 1.1,
        "watch_for": ["social_engineering", "pii_leakage", "prompt_injection"],
        "notes": "Semi-public surface. Apply standard outbound privacy checks.",
    },
    "web-page": {
        "trust_level": "low",
        "description": "Content fetched from a web page (alias for web-content)",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.1,
        "watch_for": ["prompt_injection", "unicode_bypass", "encoding_obfuscation"],
        "notes": "Alias surface for web-content. Same trust profile.",
    },
    # -----------------------------------------------------------------------
    # Execution-context surfaces — the 2026 literature (DeepTrap / SafeClawBench)
    # moved the attack surface past the user prompt into what the agent *touches*
    # at runtime: tool outputs and persistent memory. These are inbound channels
    # the agent consumes, so they get low trust and strict inbound scanning.
    # -----------------------------------------------------------------------
    "tool-return": {
        "trust_level": "low",
        "description": "Value returned by a tool / MCP server, before the agent consumes it",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.15,
        "watch_for": ["prompt_injection", "command_injection", "encoding_obfuscation"],
        "notes": "Tool returns are attacker-influenceable (a web-fetch tool can return a malicious page). Treat outputs as hostile, not just call parameters.",
    },
    "memory-write": {
        "trust_level": "low",
        "description": "Content about to be written to the agent's persistent memory",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.1,
        "watch_for": ["prompt_injection", "social_engineering", "encoding_obfuscation"],
        "notes": "Memory poisoning: untrusted content (e.g. an incoming chat message) persisted now and recalled into context later. Scan before it is stored.",
    },
    "memory-read": {
        "trust_level": "low",
        "description": "Content recalled from persistent memory back into the agent's context",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.1,
        "watch_for": ["prompt_injection", "encoding_obfuscation"],
        "notes": "Delayed-injection defence: poisoned memory written in an earlier turn re-enters context on recall. Scan on the way back in.",
    },
    "skill-metadata": {
        "trust_level": "low",
        "description": "A skill/plugin manifest, instructions (SKILL.md), or tool definitions at load time",
        "inbound_strict": True,
        "outbound_strict": False,
        "risk_multiplier": 1.15,
        "watch_for": ["prompt_injection", "command_injection", "encoding_obfuscation"],
        "notes": "Community skills are an unvetted install-time attack surface (SkillVetBench). The instruction layer carries threats static code scanners miss.",
    },
    "unknown": {
        "trust_level": "medium",
        "description": "Unknown or unspecified surface — apply moderate defaults",
        "inbound_strict": True,
        "outbound_strict": True,
        "risk_multiplier": 1.0,
        "watch_for": ["prompt_injection", "social_engineering", "pii_leakage"],
        "notes": "When in doubt, check everything.",
    },
    "public": {
        "trust_level": "low",
        "description": "Generic public surface",
        "inbound_strict": True,
        "outbound_strict": True,
        "risk_multiplier": 1.1,
        "watch_for": ["prompt_injection", "command_injection", "pii_leakage"],
        "notes": "Catch-all for any public-facing surface.",
    },
}
