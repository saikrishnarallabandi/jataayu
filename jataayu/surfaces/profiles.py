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
