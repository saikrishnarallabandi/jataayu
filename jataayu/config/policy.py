"""
Jataayu YAML Policy Configuration
===================================
Loads per-agent policy from YAML: outbound privacy rosters, capability
isolation, and effect-boundary settings. Surface profiles are NOT loaded from
here — they are a fixed table in jataayu/surfaces/profiles.py (SURFACE_PROFILES).

This file documents EVERY key the format accepts, and the format accepts nothing else
that a guard does not read. A key that no guard consumes is rejected at load with a
message naming the real source of truth — see _DEAD_KEYS. The failure mode being
designed out: writing `block_threshold: 0.3`, loading clean, and changing nothing.

Policy File Format (jataayu-policy.yml):
-----------------------------------------
version: 1                       # must be 1; see SUPPORTED_POLICY_VERSIONS

# Global defaults. Every key an agent block accepts may be written here, and an agent
# that omits the key inherits this value — as does a call naming no agent, or naming
# one that is not listed.
defaults:
  check_credentials: true
  check_high_entropy: false
  protected_names: []
  internal_codenames: []

# Per-agent policies (identified by agent name/ID)
agents:
  coding-agent:
    # Protected names for outbound guard
    protected_names: []
    # Credential checking
    check_credentials: true
    disabled_cred_rules: []
    # Capability isolation — what this agent's installed skills may collectively do.
    # allowed_capabilities (allowlist; empty = all allowed) and forbidden_capabilities
    # are enforced by jataayu_check_skillset() at install time. Capability tags:
    # exec, fs_read, fs_write, network_read, network_write, reads_secrets,
    # memory_read, memory_write.
    allowed_capabilities: [fs_read, network_read]
    forbidden_capabilities: [exec]

  prod-agent:
    # Effect-boundary behaviour (see jataayu.guards.effect_boundary).
    mode: observe                  # "enforce" (block) | "observe" (measure, don't block)
    strict_unknown_tools: false    # require approval for untrusted calls to unknown names
    tool_effects:                  # your own tool inventory — overrides the classifier
      jira.create_issue: network
      internal.run_playbook: shell
      db.query: read

  github-bot:
    protected_names: ["Alice Smith", "Bob Jones"]
    # Internal codenames — blocked on every surface. Ships empty; these are yours to supply.
    internal_codenames: ["Bluebird", "Redwood"]
    # To-market product codenames — allowed on github/public, held on social surfaces.
    gtm_codenames: ["Skylark"]
    check_credentials: true

  whatsapp-assistant:
    protected_names: ["Alice", "Bob", "Carol"]
    check_credentials: false

There is deliberately no top-level `surfaces:` block, no per-agent `surface_overrides:`
and no `allowed_surfaces:`. Surface behaviour is a fixed table in
jataayu/surfaces/profiles.py (SURFACE_PROFILES) — the guards read it directly and read
nothing here. Writing any of the three raises at load rather than being ignored.

Guard thresholds (use_llm, llm_threshold, block_threshold) are likewise not
policy-settable: they are constructor/keyword arguments on the guard, and this loader
rejects them rather than parsing values no guard would consult. Both groups may become
policy-settable later; until then the loader says so instead of pretending.

Usage:
    policy = load_policy("jataayu-policy.yml")
    agent_policy = policy.get_agent_policy("github-bot")

    # Capability isolation
    agent_policy.capability_violations(["exec", "fs_read"])

    # Outbound guard config
    privacy_cfg = agent_policy.to_privacy_config()

The outbound privacy keys (protected_names, internal_codenames, gtm_codenames,
check_credentials, disabled_cred_rules, check_high_entropy) are reached from the public
API without loading anything yourself:

    from jataayu import jataayu_check_outbound
    jataayu_check_outbound(draft, surface="discord-channel",
                           policy_file="jataayu-policy.yml", agent="github-bot")
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_logger = logging.getLogger("jataayu")

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AgentPolicy:
    """
    Policy for a specific agent instance.

    Attributes:
        name: Agent identifier.
        protected_names: Names that OutboundGuard must never emit.
        internal_codenames: Internal codenames OutboundGuard must never emit on any surface.
        gtm_codenames: To-market product codenames — allowed on github/public surfaces only.
        check_credentials: Whether OutboundGuard should scan for credentials.
        disabled_cred_rules: Credential rule IDs to disable (e.g. CRED_004).
        check_high_entropy: Enable high-entropy string detection.
        mode: "enforce" (block) or "observe" (measure only — decisions are reported
            but not enforced). Default "enforce".
        tool_effects: Tool name → EffectClass value ("read", "shell", ...). Your own
            tool inventory; overrides the built-in name classifier.
        strict_unknown_tools: Require approval for untrusted calls to tool names the
            classifier does not recognize. Default False.
        extra: Additional custom config fields.
    """

    name: str
    protected_names: list[str] = field(default_factory=list)
    internal_codenames: list[str] = field(default_factory=list)
    gtm_codenames: list[str] = field(default_factory=list)
    check_credentials: bool = True
    disabled_cred_rules: list[str] = field(default_factory=list)
    check_high_entropy: bool = False
    allowed_capabilities: list[str] = field(default_factory=list)
    forbidden_capabilities: list[str] = field(default_factory=list)
    mode: str = "enforce"
    tool_effects: dict[str, str] = field(default_factory=dict)
    strict_unknown_tools: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def is_capability_allowed(self, capability: str) -> bool:
        """
        Check if a capability is permitted for this agent (capability isolation).

        A capability is forbidden if it appears in `forbidden_capabilities`, or if
        `allowed_capabilities` is non-empty and does not contain it (allowlist mode).
        """
        if capability in self.forbidden_capabilities:
            return False
        if self.allowed_capabilities:
            return capability in self.allowed_capabilities
        return True

    def capability_violations(self, capabilities) -> list[str]:
        """Return the subset of `capabilities` this agent's policy forbids."""
        return sorted(c for c in set(capabilities) if not self.is_capability_allowed(c))

    def to_privacy_config(self):
        """
        Convert this agent policy to an OutboundGuard PrivacyConfig.

        use_llm / llm_threshold / block_threshold are left at PrivacyConfig's own
        defaults: they are not policy-settable (see _DEAD_KEYS), so there is nothing
        here to carry.

        Returns:
            PrivacyConfig instance configured from this policy.
        """
        from jataayu.guards.outbound import PrivacyConfig

        return PrivacyConfig(
            protected_names=self.protected_names,
            internal_codenames=self.internal_codenames,
            gtm_codenames=self.gtm_codenames,
            check_credentials=self.check_credentials,
            disabled_cred_rules=self.disabled_cred_rules,
            check_high_entropy=self.check_high_entropy,
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "protected_names": self.protected_names,
            "internal_codenames": self.internal_codenames,
            "gtm_codenames": self.gtm_codenames,
            "check_credentials": self.check_credentials,
            "disabled_cred_rules": self.disabled_cred_rules,
            "allowed_capabilities": self.allowed_capabilities,
            "forbidden_capabilities": self.forbidden_capabilities,
            "mode": self.mode,
            "tool_effects": self.tool_effects,
            "strict_unknown_tools": self.strict_unknown_tools,
        }


VALID_MODES = ("enforce", "observe")


_SECTION_NOUNS = {
    "agents": "agent names",
    "defaults": "settings",
}


def _reject_surfaces_block(raw: dict, where: str = "") -> None:
    """Reject a `surfaces:` block rather than parsing one nothing reads.

    The block was documented and parsed into Policy.global_surface_overrides, but no
    guard ever consulted it: InboundGuard resolves a surface through
    JataayuEngine.get_surface_profile(), which reads the fixed SURFACE_PROFILES table
    directly. A user could set risk_multiplier: 0.001 on github-issue, load clean, and
    change nothing. Failing at load is the same posture the rest of this loader takes.
    """
    if "surfaces" in raw:
        prefix = f"{where}: " if where else ""
        raise ValueError(
            f"{prefix}surfaces: surface profiles are not policy-tunable. They are a "
            f"fixed table in jataayu/surfaces/profiles.py (SURFACE_PROFILES), which is "
            f"the only thing the guards read — a `surfaces:` block here would be "
            f"silently ignored. Remove it. Per-surface tuning may become "
            f"policy-configurable later."
        )


# Keys this format used to accept, parse into AgentPolicy, and hand to no guard.
#
# Each was documented in the example file and reachable on the dataclass, so a user who
# wrote `block_threshold: 0.3` believed they had tightened a security threshold. Nothing
# read it: the outbound path pins its thresholds in jataayu/api.py::_outbound_config, the
# inbound path resolves a surface through the fixed SURFACE_PROFILES table, and no guard
# ever consulted allowed_surfaces or surface_overrides at all. Accepting a key silently is
# strictly worse than refusing it — the refusal is at least visible. Values are the
# actionable half of the message; _DEAD_KEY_SUFFIX carries the rest.
_DEAD_KEYS = {
    "block_threshold": (
        "the block threshold is a constructor argument on the guard, not policy: "
        "OutboundGuard(PrivacyConfig(block_threshold=...)), "
        "SkillVetGuard(block_threshold=...), MCPGateway(block_threshold=...). "
        "jataayu_check_outbound() pins its own and would ignore this value"
    ),
    "llm_threshold": (
        "the LLM escalation threshold is a constructor argument on the guard, not "
        "policy: InboundGuard(llm_threshold=...), "
        "OutboundGuard(PrivacyConfig(llm_threshold=...)), MCPGateway(llm_threshold=...)"
    ),
    "use_llm": (
        "the LLM slow path is a keyword argument at the call site, not policy: "
        "jataayu_check_inbound(..., use_llm=True), jataayu_check_outbound(..., "
        "use_llm=True), or InboundGuard(use_llm=...). A policy file must not be able to "
        "switch on a network call"
    ),
    "allowed_surfaces": (
        "no guard reads a per-agent surface allowlist. Surface behaviour comes from the "
        "fixed table in jataayu/surfaces/profiles.py (SURFACE_PROFILES). Gate on the "
        "surface at your own call site, or use allowed_capabilities / "
        "forbidden_capabilities, which jataayu_check_skillset() and "
        "jataayu_authorize_action() do enforce"
    ),
    "surface_overrides": (
        "per-surface tuning is not policy-settable. Its threshold keys "
        "(block_threshold, llm_threshold, use_llm) are constructor arguments on the "
        "guard, and its profile keys (trust_level, inbound_strict, outbound_strict, "
        "risk_multiplier) are the fixed table in jataayu/surfaces/profiles.py"
    ),
}

_DEAD_KEY_SUFFIX = (
    "Remove the key. It may become policy-settable later; until then the loader raises "
    "rather than accept a value no guard reads."
)


def _reject_dead_keys(cfg: dict, where: str) -> None:
    """Reject a key the loader would parse and no guard would read."""
    for key in cfg:
        if key in _DEAD_KEYS:
            raise ValueError(f"{where}: {key}: {_DEAD_KEYS[key]}. {_DEAD_KEY_SUFFIX}")


# The only `version:` this loader understands. An unknown version means the file was
# written against a format this build does not implement, and every key in it is a guess
# — which is the same silent-no-op failure _DEAD_KEYS exists to prevent, one level up.
SUPPORTED_POLICY_VERSIONS = (1,)


def _parse_version(raw: dict, where: str = "") -> int:
    """Validate `version:`, which used to be stored and never compared to anything."""
    version = raw.get("version", 1)
    # bool is an int subclass and 1.0 == 1, so neither `version: true` nor `version: 1.0`
    # may pass on equality alone.
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version not in SUPPORTED_POLICY_VERSIONS
    ):
        prefix = f"{where}: " if where else ""
        raise ValueError(
            f"{prefix}version: unsupported policy version {version!r} — this build understands "
            f"{list(SUPPORTED_POLICY_VERSIONS)}. Upgrade Jataayu, or write "
            f"`version: {SUPPORTED_POLICY_VERSIONS[-1]}`."
        )
    return version


def _mapping_section(raw: dict, key: str, where: str = "") -> dict:
    """The body of a top-level policy section, checked to be a mapping.

    An empty body (`agents:` with nothing under it) parses as None, not {}.

    from_dir() merges `agents:`/`surfaces:` out of every file BEFORE from_dict() ever
    sees them, so a check that lives only in from_dict() cannot cover the from_dir path.
    Both entry points route through here for exactly that reason: this is the third
    review round to find these two loaders diverging on the same section keys.
    """
    value = raw.get(key) or {}
    if not isinstance(value, dict):
        prefix = f"{where}: " if where else ""
        raise ValueError(
            f"{prefix}{key}: expected a mapping of {_SECTION_NOUNS[key]}, got "
            f"{type(value).__name__}"
        )
    return value


def require_bool(value: Any, where: str, key: str) -> bool:
    """Reject a non-bool where a bool is required, rather than coercing it.

    bool("false") is True, so a quoted YAML scalar turns the switch ON. For
    strict_unknown_tools that fails CLOSED (more approval gating than was asked for —
    surprising, not dangerous); for capture_content it fails OPEN, recording tool
    params the operator asked it not to keep. Either way the config silently means
    something other than what was written, which is what this loader exists to prevent.

    int is rejected too: `strict_unknown_tools: 1` is not a bool, and accepting it
    reopens the same guess-what-they-meant hole one type over.
    """
    if not isinstance(value, bool):
        raise ValueError(
            f"{where}: {key} must be true or false, got {type(value).__name__} {value!r}"
        )
    return value


def _string_list(value: Any, where: str, key: str) -> list[str]:
    """Coerce a policy list field to a fresh list of str, rejecting a bare scalar.

    `forbidden_capabilities: exec` is a YAML scalar, and list("exec") is
    ['e','x','e','c'] — which forbids nothing and fails OPEN. Rejecting at parse
    is the only place that catches it; by the time it reaches
    is_capability_allowed() it is indistinguishable from an empty policy.

    Elements are checked for the same reason one level down: `[1, 2]` clears the
    container check, but every consumer compares against a str, so it matches nothing.
    Note YAML 1.1 folds `[on, off]` to booleans, which is exactly this case.

    The returned list is always a copy: to_dict() and to_privacy_config() hand these
    lists out past the module boundary, so an aliased `defaults:` list lets one
    caller's mutation poison every agent.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(
            f"{where}: {key} must be a list, got {type(value).__name__} {value!r} — "
            f"write it as a YAML sequence (e.g. {key}: [{value!r}])"
        )
    items = list(value)
    for item in items:
        if not isinstance(item, str):
            raise ValueError(
                f"{where}: {key} entries must be strings, got "
                f'{type(item).__name__} {item!r} — quote it (e.g. {key}: ["{item}"])'
            )
    return items


# Every list field an agent block inherits from `defaults:`. get_agent_policy()'s
# unknown-agent fallback and _parse_agent() both resolve these, so the defaults block
# is a config path in its own right and is validated at parse time.
#
# EVERY list field in _parse_agent is on this tuple, and every bool field is on the one
# below. That is the rule, not a coincidence: `protected_names` and `disabled_cred_rules`
# were resolved off the agent block alone while the docs, the example file and the sibling
# keys in the same `defaults:` block all said otherwise, so a roster written in `defaults:`
# reached the wire unredacted. Adding a field here is part of adding it to _parse_agent.
_INHERITED_LIST_KEYS = (
    "allowed_capabilities",
    "forbidden_capabilities",
    "internal_codenames",
    "gtm_codenames",
    "protected_names",
    "disabled_cred_rules",
)

# Every bool field an agent block inherits from `defaults:`. All of them go through
# require_bool on both paths — `check_credentials: 0` silently switching off the whole
# credential scan is the exact coercion this loader exists to reject.
_INHERITED_BOOL_KEYS = (
    "strict_unknown_tools",
    "check_credentials",
    "check_high_entropy",
)


def _validate_effect_fields(mode: Any, tool_effects: Any, where: str) -> None:
    """Reject an unparseable mode / tool_effects block, naming the offending key.

    This is a trust boundary: `mode: obseve` silently enforcing, or
    `tool_effects: {x: shel}` silently ignored, is how a security config fails open.
    """
    from jataayu.guards.effect_boundary import EffectClass

    if mode not in VALID_MODES:
        raise ValueError(f"{where}: invalid mode {mode!r} — expected one of {list(VALID_MODES)}")
    if not isinstance(tool_effects, dict):
        raise ValueError(
            f"{where}: tool_effects must be a mapping, got {type(tool_effects).__name__}"
        )
    # 'none' is excluded: mapping a tool to EffectClass.NONE bypasses all provenance-based
    # denials and forbidden_capabilities checks (no capability tag, not in any effect set).
    valid = {e.value for e in EffectClass if e is not EffectClass.NONE}
    for tool, effect in tool_effects.items():
        if effect not in valid:
            raise ValueError(
                f"{where}: tool_effects[{tool!r}] has invalid effect {effect!r} — "
                f"expected one of {sorted(valid)}"
            )


@dataclass
class Policy:
    """
    Root policy object — contains all agent and surface policies.

    Attributes:
        version: Policy format version — validated against SUPPORTED_POLICY_VERSIONS
            at load, so an unknown one raises rather than being stored and ignored.
        agents: Dict of agent_name → AgentPolicy.
        global_surface_overrides: Always empty — the loader rejects a `surfaces:` block.
            Kept so get_surface_profile()/to_dict() keep their shape; see
            _reject_surfaces_block.
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

        # Unknown agent — an agent with an empty config block IS a defaults-only agent,
        # so parse one rather than re-deriving the inheritance here. Hand-listing the
        # inherited fields twice has now diverged twice (capability lists, then the
        # codename lists), and each divergence meant a misspelled agent name silently
        # switched off the half of the `defaults:` block that denies.
        return PolicyLoader._parse_agent(agent_name, {}, self.defaults)

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
        profile = dict(
            SURFACE_PROFILES.get(
                surface,
                {
                    "trust_level": "medium",
                    "inbound_strict": True,
                    "outbound_strict": False,
                    "risk_multiplier": 1.0,
                },
            )
        )

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
        """Load and merge all *.yml / *.yaml policy files from a directory.

        **Merge semantics** (important for security overlays):

        - **Agents** — last file wins, per agent, as a *complete replacement*.
          A second file that defines ``prod-agent:`` with only ``mode: observe``
          discards every setting from the first file (``tool_effects``,
          ``forbidden_capabilities``, etc.) and replaces the whole entry.
          The intended pattern is one authoritative file per agent; use separate
          agent names if you need compositional overrides, or a single file.
          A ``WARNING`` is logged when an agent key is defined in more than one
          file so the replacement is never silent.
        - **Surfaces** — same last-file-wins, full replacement per surface key.
        - **Defaults** — first file wins; subsequent ``defaults:`` blocks are
          ignored.  Prefix the defaults file ``00-defaults.yml`` to make this
          predictable.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        merged: dict[str, Any] = {"version": 1, "agents": {}}
        for yaml_file in sorted(directory.glob("*.y*ml")):
            raw = PolicyLoader._load_yaml(str(yaml_file))
            if not isinstance(raw, dict):
                raise ValueError(
                    f"{yaml_file}: policy must be a mapping at the top level, got "
                    f"{type(raw).__name__}"
                )
            _reject_surfaces_block(raw, str(yaml_file))
            # Per file: the merged dict below carries a synthesized version, so a bad
            # one in an individual file would never reach from_dict()'s check.
            _parse_version(raw, str(yaml_file))
            for agent, cfg in _mapping_section(raw, "agents", str(yaml_file)).items():
                if agent in merged["agents"]:
                    _logger.warning(
                        "Policy directory %s: agent %r is defined in multiple files — "
                        "%s replaces the earlier definition completely. "
                        "Security settings from the earlier file (tool_effects, "
                        "forbidden_capabilities, etc.) are discarded.",
                        directory,
                        agent,
                        yaml_file.name,
                    )
                merged["agents"][agent] = cfg
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
        if not isinstance(raw, dict):
            raise ValueError(f"policy must be a mapping at the top level, got {type(raw).__name__}")
        _reject_surfaces_block(raw)
        version = _parse_version(raw)
        defaults = _mapping_section(raw, "defaults")
        _reject_dead_keys(defaults, "defaults")

        # The defaults block feeds get_agent_policy()'s fallback for unknown agents,
        # so it is a config path in its own right and gets the same validation —
        # unconditionally, not only when some agent block happens to omit the key.
        # Otherwise a defaults-only policy parses clean and raises from
        # get_agent_policy() on every authorization request instead.
        _validate_effect_fields(
            defaults.get("mode", "enforce"),
            defaults.get("tool_effects", {}) or {},
            "defaults",
        )
        for key in _INHERITED_LIST_KEYS:
            _string_list(defaults.get(key), "defaults", key)
        for key in _INHERITED_BOOL_KEYS:
            if key in defaults:
                require_bool(defaults[key], "defaults", key)

        agents: dict[str, AgentPolicy] = {}
        for agent_name, agent_cfg in _mapping_section(raw, "agents").items():
            if not isinstance(agent_cfg, dict):
                raise ValueError(
                    f"agents.{agent_name}: expected a mapping of settings, got "
                    f"{type(agent_cfg).__name__} — an agent key with an empty body "
                    f"configures nothing"
                )
            agents[agent_name] = PolicyLoader._parse_agent(agent_name, agent_cfg, defaults)

        return Policy(
            version=version,
            agents=agents,
            defaults=defaults,
            source_path=source_path,
        )

    @staticmethod
    def _parse_agent(name: str, cfg: dict, defaults: dict) -> AgentPolicy:
        """Parse an agent config dict into an AgentPolicy.

        Every field inherits from `defaults:` when the agent block omits it.
        """
        _reject_dead_keys(cfg, f"agents.{name}")

        def inherited_list(key: str) -> list[str]:
            """Resolve a list field from the agent block, else `defaults:`, naming whichever
            one is malformed. Both paths go through the same coercion so they cannot diverge."""
            if key in cfg:
                return _string_list(cfg[key], f"agents.{name}", key)
            return _string_list(defaults.get(key), "defaults", key)

        def inherited_bool(key: str, default: bool) -> bool:
            """inherited_list() for a bool field, naming whichever block is malformed."""
            if key in cfg:
                return require_bool(cfg[key], f"agents.{name}", key)
            if key in defaults:
                return require_bool(defaults[key], "defaults", key)
            return default

        mode = cfg.get("mode", defaults.get("mode", "enforce"))
        # Validate BEFORE coercing: dict() on a list raises its own opaque ValueError,
        # which would hide which key is actually wrong.
        raw_effects = cfg.get("tool_effects", defaults.get("tool_effects", {})) or {}
        # An empty cfg is the defaults-only fallback from get_agent_policy(); blame the
        # block the bad value actually came from.
        _validate_effect_fields(mode, raw_effects, f"agents.{name}" if cfg else "defaults")
        tool_effects = dict(raw_effects)

        return AgentPolicy(
            name=name,
            protected_names=inherited_list("protected_names"),
            internal_codenames=inherited_list("internal_codenames"),
            gtm_codenames=inherited_list("gtm_codenames"),
            check_credentials=inherited_bool("check_credentials", True),
            disabled_cred_rules=inherited_list("disabled_cred_rules"),
            check_high_entropy=inherited_bool("check_high_entropy", False),
            allowed_capabilities=inherited_list("allowed_capabilities"),
            forbidden_capabilities=inherited_list("forbidden_capabilities"),
            mode=mode,
            tool_effects=tool_effects,
            strict_unknown_tools=inherited_bool("strict_unknown_tools", False),
            extra={
                k: v
                for k, v in cfg.items()
                if k
                not in (
                    "protected_names",
                    "internal_codenames",
                    "gtm_codenames",
                    "check_credentials",
                    "disabled_cred_rules",
                    "check_high_entropy",
                    "allowed_capabilities",
                    "forbidden_capabilities",
                    "mode",
                    "tool_effects",
                    "strict_unknown_tools",
                )
            },
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
                    "PyYAML is required to load .yml policy files. Install with: pip install pyyaml"
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

    # Return empty policy with safe defaults. Only policy-settable keys belong here:
    # get_agent_policy() runs this dict back through _parse_agent(), which rejects the
    # rest — a built-in default naming one would make load_policy() raise on itself.
    return Policy(
        version=1,
        defaults={
            "check_credentials": True,
            "check_high_entropy": False,
        },
    )
