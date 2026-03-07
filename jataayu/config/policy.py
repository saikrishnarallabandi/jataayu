"""
Jataayu YAML Policy Configuration
===================================
Loads per-agent surface policies from YAML files, replacing hardcoded
profile lookups throughout the Jataayu codebase.

Policy File Format (jataayu-policy.yml):
-----------------------------------------
version: 1

# Global defaults applied when no agent-specific rule matches
defaults:
  block_threshold: 0.9
  llm_threshold: 0.35
  use_llm: false
  check_credentials: true
  check_high_entropy: false

# Per-agent policies (identified by agent name/ID)
agents:
  coding-agent:
    # Surface allowlist — only these surfaces are permitted for this agent
    allowed_surfaces: [coding-task, internal, direct-message]
    # Surface-specific overrides for this agent
    surface_overrides:
      coding-task:
        block_threshold: 0.95   # more permissive — shell commands expected
        inbound_strict: false
    # Protected names for outbound guard
    protected_names: []
    # Credential checking
    check_credentials: true
    disabled_cred_rules: []

  github-bot:
    allowed_surfaces: [github-issue, github-pr, github-comment, internal]
    surface_overrides:
      github-issue:
        block_threshold: 0.70
        inbound_strict: true
    protected_names: ["Alice Smith", "Bob Jones"]
    check_credentials: true
    use_llm: true
    llm_threshold: 0.4

  whatsapp-assistant:
    allowed_surfaces: [group-chat, direct-message, internal]
    surface_overrides:
      group-chat:
        outbound_strict: true
        block_threshold: 0.65
    protected_names: ["Veda", "Tarak", "Suchi"]
    check_credentials: false

# Surface profile overrides (global, applies to all agents unless overridden per-agent)
surfaces:
  github-issue:
    trust_level: low
    inbound_strict: true
    outbound_strict: false
    risk_multiplier: 1.2
  coding-task:
    trust_level: medium
    inbound_strict: false
    risk_multiplier: 0.7

Usage:
    policy = load_policy("jataayu-policy.yml")
    agent_policy = policy.get_agent_policy("github-bot")

    # Check if a surface is allowed for this agent
    if not agent_policy.is_surface_allowed("web-content"):
        raise PermissionError("Agent not permitted on web-content surface")

    # Get effective block threshold for a surface
    threshold = agent_policy.get_block_threshold("github-issue")

    # Get outbound guard config
    from jataayu.guards.outbound import PrivacyConfig
    privacy_cfg = agent_policy.to_privacy_config()
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SurfacePolicy:
    """Policy for a specific surface within an agent context."""
    surface: str
    block_threshold: float = 0.9
    llm_threshold: float = 0.35
    use_llm: bool = False
    inbound_strict: bool = True
    outbound_strict: bool = False
    risk_multiplier: float = 1.0
    trust_level: str = "medium"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "surface": self.surface,
            "block_threshold": self.block_threshold,
            "llm_threshold": self.llm_threshold,
            "use_llm": self.use_llm,
            "inbound_strict": self.inbound_strict,
            "outbound_strict": self.outbound_strict,
            "risk_multiplier": self.risk_multiplier,
            "trust_level": self.trust_level,
        }


@dataclass
class AgentPolicy:
    """
    Policy for a specific agent instance.

    Attributes:
        name: Agent identifier.
        allowed_surfaces: If non-empty, only these surfaces are permitted.
            Empty list = all surfaces allowed.
        surface_overrides: Per-surface configuration overrides.
        protected_names: Names that OutboundGuard must never emit.
        check_credentials: Whether OutboundGuard should scan for credentials.
        disabled_cred_rules: Credential rule IDs to disable (e.g. CRED_004).
        check_high_entropy: Enable high-entropy string detection.
        use_llm: Whether to use LLM slow path (agent-level default).
        llm_threshold: LLM escalation threshold (agent-level default).
        block_threshold: Block threshold (agent-level default).
        extra: Additional custom config fields.
    """
    name: str
    allowed_surfaces: list[str] = field(default_factory=list)
    surface_overrides: dict[str, SurfacePolicy] = field(default_factory=dict)
    protected_names: list[str] = field(default_factory=list)
    check_credentials: bool = True
    disabled_cred_rules: list[str] = field(default_factory=list)
    check_high_entropy: bool = False
    use_llm: bool = False
    llm_threshold: float = 0.35
    block_threshold: float = 0.9
    extra: dict[str, Any] = field(default_factory=dict)

    def is_surface_allowed(self, surface: str) -> bool:
        """Check if a surface is permitted for this agent."""
        if not self.allowed_surfaces:
            return True  # Empty = all allowed
        return surface in self.allowed_surfaces

    def get_surface_policy(self, surface: str) -> SurfacePolicy:
        """Get the effective SurfacePolicy for a surface (with agent defaults)."""
        if surface in self.surface_overrides:
            return self.surface_overrides[surface]
        # Return a SurfacePolicy with agent-level defaults
        return SurfacePolicy(
            surface=surface,
            block_threshold=self.block_threshold,
            llm_threshold=self.llm_threshold,
            use_llm=self.use_llm,
        )

    def get_block_threshold(self, surface: str) -> float:
        """Get the effective block threshold for a surface."""
        return self.get_surface_policy(surface).block_threshold

    def to_privacy_config(self):
        """
        Convert this agent policy to an OutboundGuard PrivacyConfig.

        Returns:
            PrivacyConfig instance configured from this policy.
        """
        from jataayu.guards.outbound import PrivacyConfig
        return PrivacyConfig(
            protected_names=self.protected_names,
            use_llm=self.use_llm,
            llm_threshold=self.llm_threshold,
            block_threshold=self.block_threshold,
            check_credentials=self.check_credentials,
            disabled_cred_rules=self.disabled_cred_rules,
            check_high_entropy=self.check_high_entropy,
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "allowed_surfaces": self.allowed_surfaces,
            "surface_overrides": {k: v.to_dict() for k, v in self.surface_overrides.items()},
            "protected_names": self.protected_names,
            "check_credentials": self.check_credentials,
            "disabled_cred_rules": self.disabled_cred_rules,
            "use_llm": self.use_llm,
            "llm_threshold": self.llm_threshold,
            "block_threshold": self.block_threshold,
        }


@dataclass
class Policy:
    """
    Root policy object — contains all agent and surface policies.

    Attributes:
        version: Policy format version.
        agents: Dict of agent_name → AgentPolicy.
        global_surface_overrides: Global surface profile overrides.
        defaults: Global defaults applied to all agents.
        source_path: Path to the YAML file this was loaded from (if any).
    """
    version: int = 1
    agents: dict[str, AgentPolicy] = field(default_factory=dict)
    global_surface_overrides: dict[str, dict] = field(default_factory=dict)
    defaults: dict[str, Any] = field(default_factory=dict)
    source_path: Optional[str] = None

    def get_agent_policy(self, agent_name: str) -> AgentPolicy:
        """
        Get the policy for a specific agent. Falls back to defaults if not found.

        Args:
            agent_name: Agent identifier (as defined in policy YAML).

        Returns:
            AgentPolicy — never raises, returns a defaults-only policy if unknown.
        """
        if agent_name in self.agents:
            return self.agents[agent_name]

        # Unknown agent — return policy built from global defaults
        return AgentPolicy(
            name=agent_name,
            use_llm=self.defaults.get("use_llm", False),
            llm_threshold=self.defaults.get("llm_threshold", 0.35),
            block_threshold=self.defaults.get("block_threshold", 0.9),
            check_credentials=self.defaults.get("check_credentials", True),
            check_high_entropy=self.defaults.get("check_high_entropy", False),
        )

    def get_surface_profile(self, surface: str) -> dict:
        """
        Get the effective surface profile, merging global overrides with built-in profiles.

        Args:
            surface: Surface name (e.g. "github-issue").

        Returns:
            Profile dict — starts from built-in SURFACE_PROFILES, then applies overrides.
        """
        from jataayu.surfaces.profiles import SURFACE_PROFILES

        # Start with built-in profile
        profile = dict(SURFACE_PROFILES.get(surface, {
            "trust_level": "medium",
            "inbound_strict": True,
            "outbound_strict": False,
            "risk_multiplier": 1.0,
        }))

        # Apply global surface overrides from policy
        if surface in self.global_surface_overrides:
            profile.update(self.global_surface_overrides[surface])

        return profile

    def list_agents(self) -> list[str]:
        """Return list of agent names defined in this policy."""
        return list(self.agents.keys())

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "defaults": self.defaults,
            "agents": {k: v.to_dict() for k, v in self.agents.items()},
            "global_surface_overrides": self.global_surface_overrides,
        }


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------

class PolicyLoader:
    """
    Loads Jataayu policy from YAML files.

    Supports:
    - Single YAML file: PolicyLoader.from_file("jataayu-policy.yml")
    - Directory of YAML files: PolicyLoader.from_dir("policy/")
    - Dict (e.g., from tests): PolicyLoader.from_dict({"version": 1, ...})
    - Environment variable: JATAAYU_POLICY_FILE

    Graceful degradation: if PyYAML is not installed, loads from a simple
    built-in default policy instead of raising.
    """

    @staticmethod
    def from_file(path: str | Path) -> Policy:
        """Load policy from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        raw = PolicyLoader._load_yaml(str(path))
        return PolicyLoader.from_dict(raw, source_path=str(path))

    @staticmethod
    def from_dir(directory: str | Path) -> Policy:
        """Load and merge all *.yml / *.yaml policy files from a directory."""
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        merged: dict[str, Any] = {"version": 1, "agents": {}, "surfaces": {}}
        for yaml_file in sorted(directory.glob("*.y*ml")):
            raw = PolicyLoader._load_yaml(str(yaml_file))
            # Merge agents
            for agent, cfg in raw.get("agents", {}).items():
                merged["agents"][agent] = cfg
            # Merge surface overrides
            for surf, cfg in raw.get("surfaces", {}).items():
                merged["surfaces"][surf] = cfg
            # Use first file's defaults
            if "defaults" not in merged and "defaults" in raw:
                merged["defaults"] = raw["defaults"]

        return PolicyLoader.from_dict(merged, source_path=str(directory))

    @staticmethod
    def from_env() -> Optional[Policy]:
        """Load from JATAAYU_POLICY_FILE env var if set."""
        path = os.environ.get("JATAAYU_POLICY_FILE")
        if not path:
            return None
        return PolicyLoader.from_file(path)

    @staticmethod
    def from_dict(raw: dict, source_path: Optional[str] = None) -> Policy:
        """Parse a policy dict (already loaded from YAML) into a Policy object."""
        defaults = raw.get("defaults", {})
        global_surfaces = raw.get("surfaces", {})

        agents: dict[str, AgentPolicy] = {}
        for agent_name, agent_cfg in raw.get("agents", {}).items():
            agents[agent_name] = PolicyLoader._parse_agent(
                agent_name, agent_cfg, defaults
            )

        return Policy(
            version=int(raw.get("version", 1)),
            agents=agents,
            global_surface_overrides=global_surfaces,
            defaults=defaults,
            source_path=source_path,
        )

    @staticmethod
    def _parse_agent(name: str, cfg: dict, defaults: dict) -> AgentPolicy:
        """Parse an agent config dict into an AgentPolicy."""
        surface_overrides: dict[str, SurfacePolicy] = {}
        for surf_name, surf_cfg in cfg.get("surface_overrides", {}).items():
            surface_overrides[surf_name] = SurfacePolicy(
                surface=surf_name,
                block_threshold=surf_cfg.get(
                    "block_threshold", cfg.get("block_threshold", defaults.get("block_threshold", 0.9))
                ),
                llm_threshold=surf_cfg.get(
                    "llm_threshold", cfg.get("llm_threshold", defaults.get("llm_threshold", 0.35))
                ),
                use_llm=surf_cfg.get(
                    "use_llm", cfg.get("use_llm", defaults.get("use_llm", False))
                ),
                inbound_strict=surf_cfg.get("inbound_strict", True),
                outbound_strict=surf_cfg.get("outbound_strict", False),
                risk_multiplier=surf_cfg.get("risk_multiplier", 1.0),
                trust_level=surf_cfg.get("trust_level", "medium"),
                extra={k: v for k, v in surf_cfg.items()
                       if k not in ("block_threshold", "llm_threshold", "use_llm",
                                    "inbound_strict", "outbound_strict", "risk_multiplier",
                                    "trust_level")},
            )

        return AgentPolicy(
            name=name,
            allowed_surfaces=cfg.get("allowed_surfaces", []),
            surface_overrides=surface_overrides,
            protected_names=cfg.get("protected_names", []),
            check_credentials=cfg.get("check_credentials", defaults.get("check_credentials", True)),
            disabled_cred_rules=cfg.get("disabled_cred_rules", []),
            check_high_entropy=cfg.get("check_high_entropy", defaults.get("check_high_entropy", False)),
            use_llm=cfg.get("use_llm", defaults.get("use_llm", False)),
            llm_threshold=cfg.get("llm_threshold", defaults.get("llm_threshold", 0.35)),
            block_threshold=cfg.get("block_threshold", defaults.get("block_threshold", 0.9)),
            extra={k: v for k, v in cfg.items()
                   if k not in ("allowed_surfaces", "surface_overrides", "protected_names",
                                "check_credentials", "disabled_cred_rules", "check_high_entropy",
                                "use_llm", "llm_threshold", "block_threshold")},
        )

    @staticmethod
    def _load_yaml(path: str) -> dict:
        """Load a YAML file, falling back to JSON if PyYAML is not available."""
        try:
            import yaml  # type: ignore[import]
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            # Graceful degradation — try JSON
            import json
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except Exception:
                raise ImportError(
                    "PyYAML is required to load .yml policy files. "
                    "Install with: pip install pyyaml"
                )
        except Exception as e:
            raise ValueError(f"Failed to parse policy file {path!r}: {e}") from e


def load_policy(path: Optional[str | Path] = None) -> Policy:
    """
    Convenience function — load policy from file, directory, or env var.

    Priority:
    1. Explicit path argument (if provided)
    2. JATAAYU_POLICY_FILE environment variable
    3. Default built-in policy (safe defaults)

    Args:
        path: Path to a YAML policy file or directory.

    Returns:
        Policy object ready to use.
    """
    if path is not None:
        p = Path(path)
        if p.is_dir():
            return PolicyLoader.from_dir(p)
        return PolicyLoader.from_file(p)

    env_policy = PolicyLoader.from_env()
    if env_policy is not None:
        return env_policy

    # Return empty policy with safe defaults
    return Policy(
        version=1,
        defaults={
            "block_threshold": 0.9,
            "llm_threshold": 0.35,
            "use_llm": False,
            "check_credentials": True,
            "check_high_entropy": False,
        },
    )
