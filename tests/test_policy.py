"""
Tests for Issue #6 — YAML policy configuration.
"""
import os
import tempfile
from pathlib import Path

import pytest
from jataayu.config.policy import Policy, PolicyLoader, load_policy, AgentPolicy, SurfacePolicy


# ---------------------------------------------------------------------------
# Sample YAML policy content
# ---------------------------------------------------------------------------

SAMPLE_POLICY_YAML = """
version: 1

defaults:
  block_threshold: 0.85
  llm_threshold: 0.4
  use_llm: false
  check_credentials: true
  check_high_entropy: false

agents:
  coding-agent:
    allowed_surfaces:
      - coding-task
      - internal
      - direct-message
    surface_overrides:
      coding-task:
        block_threshold: 0.95
        inbound_strict: false
        risk_multiplier: 0.7
    protected_names: []
    check_credentials: false

  github-bot:
    allowed_surfaces:
      - github-issue
      - github-pr
      - github-comment
      - internal
    surface_overrides:
      github-issue:
        block_threshold: 0.70
        inbound_strict: true
        risk_multiplier: 1.2
    protected_names:
      - "Alice Smith"
      - "Bob Jones"
    check_credentials: true
    use_llm: false
    llm_threshold: 0.4

  privacy-bot:
    allowed_surfaces: []
    protected_names:
      - Alice
      - Bob
    check_credentials: false
"""


@pytest.fixture
def policy_file(tmp_path):
    """Create a temp YAML policy file."""
    p = tmp_path / "jataayu-policy.yml"
    p.write_text(SAMPLE_POLICY_YAML)
    return str(p)


@pytest.fixture
def policy(policy_file):
    return PolicyLoader.from_file(policy_file)


class TestPolicyLoading:
    def test_load_from_file(self, policy_file):
        p = PolicyLoader.from_file(policy_file)
        assert p.version == 1
        assert "coding-agent" in p.agents
        assert "github-bot" in p.agents

    def test_load_from_dict(self):
        raw = {
            "version": 1,
            "defaults": {"block_threshold": 0.8},
            "agents": {
                "test-agent": {
                    "allowed_surfaces": ["internal"],
                }
            }
        }
        p = PolicyLoader.from_dict(raw)
        assert "test-agent" in p.agents

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            PolicyLoader.from_file("/nonexistent/path/policy.yml")

    def test_load_policy_returns_default_when_no_file(self):
        p = load_policy()  # no path, no env var
        assert isinstance(p, Policy)
        assert p.version == 1

    def test_load_policy_from_env(self, policy_file, monkeypatch):
        monkeypatch.setenv("JATAAYU_POLICY_FILE", policy_file)
        p = load_policy()
        assert "coding-agent" in p.agents

    def test_load_from_dir(self, tmp_path):
        p1 = tmp_path / "agents.yml"
        p1.write_text("""
version: 1
agents:
  agent-a:
    allowed_surfaces: [internal]
""")
        p2 = tmp_path / "more-agents.yml"
        p2.write_text("""
version: 1
agents:
  agent-b:
    allowed_surfaces: [github-issue]
""")
        policy = PolicyLoader.from_dir(tmp_path)
        assert "agent-a" in policy.agents
        assert "agent-b" in policy.agents


class TestAgentPolicy:
    def test_coding_agent_allowed_surfaces(self, policy):
        agent = policy.get_agent_policy("coding-agent")
        assert agent.is_surface_allowed("coding-task")
        assert agent.is_surface_allowed("internal")
        assert not agent.is_surface_allowed("github-issue")
        assert not agent.is_surface_allowed("web-content")

    def test_agent_with_no_allowed_surfaces_allows_all(self, policy):
        """Empty allowed_surfaces means all surfaces permitted."""
        agent = policy.get_agent_policy("privacy-bot")
        assert agent.is_surface_allowed("github-issue")
        assert agent.is_surface_allowed("web-content")
        assert agent.is_surface_allowed("group-chat")

    def test_github_bot_surface_override(self, policy):
        agent = policy.get_agent_policy("github-bot")
        sp = agent.get_surface_policy("github-issue")
        assert sp.block_threshold == 0.70
        assert sp.inbound_strict is True

    def test_coding_agent_surface_override(self, policy):
        agent = policy.get_agent_policy("coding-agent")
        sp = agent.get_surface_policy("coding-task")
        assert sp.block_threshold == 0.95
        assert sp.inbound_strict is False

    def test_unknown_agent_returns_defaults(self, policy):
        agent = policy.get_agent_policy("nonexistent-agent")
        assert agent.name == "nonexistent-agent"
        assert agent.block_threshold == 0.85  # from defaults

    def test_agent_protected_names(self, policy):
        agent = policy.get_agent_policy("github-bot")
        assert "Alice Smith" in agent.protected_names
        assert "Bob Jones" in agent.protected_names

    def test_agent_credentials_disabled(self, policy):
        agent = policy.get_agent_policy("coding-agent")
        assert agent.check_credentials is False

    def test_agent_credentials_enabled(self, policy):
        agent = policy.get_agent_policy("github-bot")
        assert agent.check_credentials is True


class TestSurfacePolicy:
    def test_surface_profile_is_the_builtin_table(self, policy):
        """get_surface_profile() returns SURFACE_PROFILES verbatim — nothing overrides it."""
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        assert policy.get_surface_profile("github-issue") == SURFACE_PROFILES["github-issue"]

    def test_surface_profile_fallback_to_builtin(self, policy):
        """Surfaces not overridden in policy should use built-in profiles."""
        profile = policy.get_surface_profile("group-chat")
        assert profile.get("trust_level") == "medium"

    def test_surface_policy_fallback_for_unknown_surface(self, policy):
        agent = policy.get_agent_policy("coding-agent")
        sp = agent.get_surface_policy("unknown-surface")
        # Should return defaults with agent-level block_threshold
        assert sp.block_threshold == agent.block_threshold

    def test_surface_policy_to_dict(self):
        sp = SurfacePolicy(
            surface="github-issue",
            block_threshold=0.75,
            inbound_strict=True,
        )
        d = sp.to_dict()
        assert d["surface"] == "github-issue"
        assert d["block_threshold"] == 0.75
        assert d["inbound_strict"] is True


class TestToPrivacyConfig:
    def test_to_privacy_config_protected_names(self, policy):
        agent = policy.get_agent_policy("github-bot")
        config = agent.to_privacy_config()
        assert "Alice Smith" in config.protected_names

    def test_to_privacy_config_credentials(self, policy):
        agent = policy.get_agent_policy("coding-agent")
        config = agent.to_privacy_config()
        assert config.check_credentials is False

    def test_to_privacy_config_block_threshold(self, policy):
        agent = policy.get_agent_policy("github-bot")
        config = agent.to_privacy_config()
        assert config.block_threshold == agent.block_threshold


class TestPolicyToDict:
    def test_policy_to_dict_structure(self, policy):
        d = policy.to_dict()
        assert "version" in d
        assert "agents" in d
        assert "defaults" in d
        assert "coding-agent" in d["agents"]

    def test_agent_policy_to_dict(self, policy):
        agent = policy.get_agent_policy("github-bot")
        d = agent.to_dict()
        assert d["name"] == "github-bot"
        assert "allowed_surfaces" in d
        assert "protected_names" in d
        assert "surface_overrides" in d


class TestDefaultPolicy:
    def test_default_policy_has_safe_defaults(self):
        p = load_policy()
        # Default policy should have safe block threshold
        agent = p.get_agent_policy("any-agent")
        assert agent.block_threshold <= 0.95
        assert agent.check_credentials is True

    def test_default_policy_allows_all_surfaces(self):
        p = load_policy()
        agent = p.get_agent_policy("test")
        assert agent.is_surface_allowed("github-issue")
        assert agent.is_surface_allowed("group-chat")

    def test_list_agents(self, policy):
        agents = policy.list_agents()
        assert "coding-agent" in agents
        assert "github-bot" in agents
        assert "privacy-bot" in agents


# ---------------------------------------------------------------------------
# Effect-boundary policy fields: mode / tool_effects / strict_unknown_tools.
#
# This is the test that has never existed in this repo — a policy YAML loaded through
# load_policy() into EffectBoundary(policy=...) actually CHANGING a verdict. Without it,
# the loader could silently produce inert config and every other test would still pass.
# ---------------------------------------------------------------------------

EFFECT_POLICY_YAML = """
version: 1

defaults:
  block_threshold: 0.85

agents:
  prod:
    mode: observe
    strict_unknown_tools: true
    tool_effects:
      jira.create_issue: network
      internal.run_playbook: shell
      db.query: read
"""


@pytest.fixture
def effect_policy_file():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(EFFECT_POLICY_YAML)
        path = f.name
    yield path
    os.unlink(path)


class TestEffectPolicyWiring:
    def test_fields_survive_the_yaml_round_trip(self, effect_policy_file):
        agent = load_policy(effect_policy_file).get_agent_policy("prod")
        assert agent.mode == "observe"
        assert agent.strict_unknown_tools is True
        assert agent.tool_effects["internal.run_playbook"] == "shell"

    def test_yaml_tool_effects_changes_a_verdict(self, effect_policy_file):
        """The load-bearing assertion: config from a file moves the decision."""
        from jataayu.guards.effect_boundary import (
            EffectBoundary, Value, Provenance, EffectClass, Decision,
        )

        agent = load_policy(effect_policy_file).get_agent_policy("prod")
        untrusted = [Value("payload", Provenance.UNTRUSTED)]

        # Without the policy this name is unrecognized -> READ -> ALLOW.
        plain = EffectBoundary().preview("internal.run_playbook", {"x": 1}, untrusted)
        assert plain.effect_class is EffectClass.READ
        assert plain.decision is Decision.ALLOW

        # With it, the name is a shell effect. Observe mode reports, does not enforce.
        pv = EffectBoundary(policy=agent).preview("internal.run_playbook", {"x": 1}, untrusted)
        assert pv.effect_class is EffectClass.SHELL
        assert pv.would_decision is Decision.DENY
        assert pv.decision is Decision.ALLOW

    def test_yaml_strict_flag_changes_a_verdict(self, effect_policy_file):
        from jataayu.guards.effect_boundary import EffectBoundary, Value, Provenance, Decision

        agent = load_policy(effect_policy_file).get_agent_policy("prod")
        b = EffectBoundary(policy=agent, mode="enforce")   # isolate strict from observe
        pv = b.preview("frobnicate.widget", {"x": 1}, [Value("p", Provenance.UNTRUSTED)])
        assert pv.decision is Decision.NEEDS_APPROVAL

    def test_kwarg_beats_policy_for_mode(self, effect_policy_file):
        from jataayu.guards.effect_boundary import EffectBoundary

        agent = load_policy(effect_policy_file).get_agent_policy("prod")
        assert EffectBoundary(policy=agent).mode == "observe"
        assert EffectBoundary(policy=agent, mode="enforce").mode == "enforce"

    def test_tool_effects_merges_rather_than_replaces(self, effect_policy_file):
        from jataayu.guards.effect_boundary import EffectBoundary, EffectClass

        agent = load_policy(effect_policy_file).get_agent_policy("prod")
        b = EffectBoundary(policy=agent, tool_effects={"local.tool": "shell"})

        assert b.classify("local.tool") is EffectClass.SHELL          # from the kwarg
        assert b.classify("jira.create_issue") is EffectClass.NETWORK  # from the file

    def test_kwarg_wins_per_key_on_conflict(self, effect_policy_file):
        from jataayu.guards.effect_boundary import EffectBoundary, EffectClass

        agent = load_policy(effect_policy_file).get_agent_policy("prod")
        b = EffectBoundary(policy=agent, tool_effects={"db.query": "shell"})
        assert b.classify("db.query") is EffectClass.SHELL

    def test_defaults_block_applies_without_naming_an_agent(self):
        """`defaults: {mode: observe}` must work even when no agent is named."""
        yaml_text = "version: 1\ndefaults:\n  mode: observe\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(yaml_text)
            path = f.name
        try:
            assert load_policy(path).get_agent_policy("").mode == "observe"
        finally:
            os.unlink(path)

    def test_policy_file_alone_is_load_bearing_through_the_api(self, effect_policy_file):
        """policy_file without agent= used to resolve to None, making the file inert."""
        from jataayu import jataayu_authorize_action

        d = jataayu_authorize_action(
            "internal.run_playbook", {"x": 1},
            policy_file=effect_policy_file, agent="prod",
        )
        assert d["effect_class"] == "shell"
        assert d["would_decision"] == "deny"

    def test_agent_to_dict_carries_the_new_fields(self, effect_policy_file):
        d = load_policy(effect_policy_file).get_agent_policy("prod").to_dict()
        assert d["mode"] == "observe"
        assert d["strict_unknown_tools"] is True
        assert d["tool_effects"]["db.query"] == "read"


class TestEffectPolicyValidation:
    """A typo in a security config must fail loudly, not silently fail open."""

    def _load(self, yaml_text):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(yaml_text)
            path = f.name
        try:
            return load_policy(path)
        finally:
            os.unlink(path)

    def test_misspelled_mode_raises_naming_the_agent(self):
        with pytest.raises(ValueError, match="obseve"):
            self._load("version: 1\nagents:\n  prod:\n    mode: obseve\n")

    def test_invalid_effect_value_raises_naming_the_tool(self):
        with pytest.raises(ValueError, match="db.query"):
            self._load(
                "version: 1\nagents:\n  prod:\n    tool_effects:\n      db.query: shel\n"
            )

    def test_agent_with_an_empty_body_raises_naming_the_agent(self):
        with pytest.raises(ValueError, match="agents.prod"):
            self._load("version: 1\nagents:\n  prod:\n")

    def test_misspelled_mode_in_defaults_raises(self):
        with pytest.raises(ValueError, match="defaults"):
            self._load("version: 1\ndefaults:\n  mode: obseve\n")

    def test_non_mapping_tool_effects_raises(self):
        with pytest.raises(ValueError, match="mapping"):
            self._load("version: 1\nagents:\n  prod:\n    tool_effects: [a, b]\n")

    def test_valid_policy_without_the_new_fields_still_loads(self):
        p = self._load("version: 1\nagents:\n  prod:\n    check_credentials: true\n")
        agent = p.get_agent_policy("prod")
        assert agent.mode == "enforce"
        assert agent.strict_unknown_tools is False
        assert agent.tool_effects == {}


DEFAULTS_FORBID = (
    "version: 1\n"
    "defaults:\n"
    "  forbidden_capabilities: [exec, fs_write]\n"
    "agents:\n"
    "  prod: {}\n"
)


class TestDefaultsCapabilityFallback:
    """A `defaults:` block that FORBIDS must not go inert when no agent matches.

    The fallback propagated only the permissive fields (mode / tool_effects /
    strict_unknown_tools), so an unnamed or misspelled agent failed open.
    """

    @pytest.fixture
    def policy_path(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(DEFAULTS_FORBID)
        return str(p)

    def test_fallback_inherits_forbidden_capabilities(self, policy_path):
        assert load_policy(policy_path).get_agent_policy("").forbidden_capabilities == [
            "exec", "fs_write",
        ]

    @pytest.mark.parametrize("agent", [None, "prod", "prodd"])
    def test_shell_denies_with_or_without_a_matching_agent(self, policy_path, agent):
        """Named, unnamed, and typo'd all deny — the typo used to allow."""
        from jataayu import jataayu_authorize_action

        d = jataayu_authorize_action(
            "shell.exec", {"command": "ls"}, untrusted=False,
            policy_file=policy_path, agent=agent,
        )
        assert d["decision"] == "deny"
        assert "exec" in d["violations"]

    def test_fallback_does_not_alias_the_defaults_dict(self, policy_path):
        policy = load_policy(policy_path)
        policy.get_agent_policy("").forbidden_capabilities.append("fs_read")
        assert policy.defaults["forbidden_capabilities"] == ["exec", "fs_write"]


class TestPolicyFileHotReload:
    """observe -> enforce must take effect on an edit, without a process restart."""

    def _write(self, path, mode):
        path.write_text(
            f"version: 1\nagents:\n  prod:\n    mode: {mode}\n"
            f"    tool_effects:\n      internal.run_playbook: shell\n"
        )

    def test_flipping_mode_in_the_file_starts_enforcing(self, tmp_path):
        from jataayu import jataayu_authorize_action

        p = tmp_path / "jataayu-policy.yml"
        self._write(p, "observe")
        first = jataayu_authorize_action(
            "internal.run_playbook", {"x": 1}, policy_file=str(p), agent="prod",
        )
        assert first["decision"] == "allow"
        assert first["would_decision"] == "deny"

        self._write(p, "enforce")
        after = jataayu_authorize_action(
            "internal.run_playbook", {"x": 1}, policy_file=str(p), agent="prod",
        )
        assert after["decision"] == "deny"

    def test_edit_within_one_mtime_tick_still_takes_effect(self, tmp_path):
        """The reload must not depend on the filesystem's clock granularity.

        'observe' and 'enforce' are both 7 bytes, and back-to-back saves on ext4 share an
        st_mtime_ns ~95% of the time — so a (mtime, size) cache key serves the stale
        observe policy PERMANENTLY. Pinning both stats identical makes that deterministic.
        """
        from jataayu import jataayu_authorize_action

        p = tmp_path / "jataayu-policy.yml"
        self._write(p, "observe")
        st = p.stat()
        assert jataayu_authorize_action(
            "internal.run_playbook", {"x": 1}, policy_file=str(p), agent="prod",
        )["decision"] == "allow"

        self._write(p, "enforce")
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        assert p.stat().st_mtime_ns == st.st_mtime_ns
        assert p.stat().st_size == st.st_size

        for _ in range(2):   # ...and stays enforcing, not just on the first re-read
            assert jataayu_authorize_action(
                "internal.run_playbook", {"x": 1}, policy_file=str(p), agent="prod",
            )["decision"] == "deny"

    def test_a_policy_file_deleted_after_a_hit_raises(self, tmp_path):
        """A cached hit must not outlive the file it was parsed from."""
        from jataayu import api

        p = tmp_path / "jataayu-policy.yml"
        self._write(p, "enforce")
        assert api._load_agent_policy(str(p), "prod").mode == "enforce"

        p.unlink()
        with pytest.raises(FileNotFoundError):
            api._load_agent_policy(str(p), "prod")

    def test_a_policy_file_replaced_by_rename_takes_effect(self, tmp_path):
        """The atomic-save pattern (write temp, os.replace) is how editors save."""
        from jataayu import api

        p = tmp_path / "jataayu-policy.yml"
        self._write(p, "observe")
        assert api._load_agent_policy(str(p), "prod").mode == "observe"

        tmp = tmp_path / "staged.yml"
        self._write(tmp, "enforce")
        os.replace(tmp, p)
        assert api._load_agent_policy(str(p), "prod").mode == "enforce"

    def test_a_policy_directory_reloads_on_an_edit(self, tmp_path):
        from jataayu import api

        d = tmp_path / "policy.d"
        d.mkdir()
        self._write(d / "a.yml", "observe")
        assert api._load_agent_policy(str(d), "prod").mode == "observe"

        self._write(d / "a.yml", "enforce")
        os.utime(d / "a.yml", ns=(0, 0))
        assert api._load_agent_policy(str(d), "prod").mode == "enforce"

    def test_tightening_capabilities_in_the_file_takes_effect(self, tmp_path):
        from jataayu import jataayu_authorize_action

        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  prod: {}\n")
        assert jataayu_authorize_action(
            "shell.exec", {"x": 1}, untrusted=False, policy_file=str(p), agent="prod",
        )["decision"] == "allow"

        p.write_text("version: 1\nagents:\n  prod:\n    forbidden_capabilities: [exec]\n")
        assert jataayu_authorize_action(
            "shell.exec", {"x": 1}, untrusted=False, policy_file=str(p), agent="prod",
        )["decision"] == "deny"

    def test_an_edit_takes_effect_on_the_very_next_call(self, tmp_path):
        """No stat manipulation, no sleep, no cache to clear — just write and call.

        This is the whole contract. It held for none of the three caches that lived
        here; each one served the stale `observe` policy after the file said `enforce`.
        """
        from jataayu import api

        p = tmp_path / "jataayu-policy.yml"
        for mode in ("observe", "enforce", "observe", "enforce"):
            self._write(p, mode)
            assert api._load_agent_policy(str(p), "prod").mode == mode

    def test_every_call_re_reads_the_file(self, tmp_path, monkeypatch):
        """The parse is deliberately NOT cached — see _load_agent_policy's docstring."""
        from jataayu import api
        from jataayu.config import policy as policy_mod

        p = tmp_path / "jataayu-policy.yml"
        self._write(p, "enforce")

        calls = []
        real = policy_mod.PolicyLoader._load_yaml
        monkeypatch.setattr(
            policy_mod.PolicyLoader, "_load_yaml",
            staticmethod(lambda path: (calls.append(path), real(path))[1]),
        )

        for _ in range(3):
            api._load_agent_policy(str(p), "prod")
        assert len(calls) == 3

    def test_a_concurrent_edit_never_yields_a_policy_that_was_never_on_disk(self, tmp_path):
        """The TOCTOU the digest cache had: a writer flipping the file while a reader
        loops must never poison the reader into a mode the file no longer holds."""
        import threading

        from jataayu import api

        p = tmp_path / "jataayu-policy.yml"
        self._write(p, "enforce")
        stop = threading.Event()

        staged = tmp_path / "staged.yml"

        def churn():
            # os.replace, not write_text: a truncate-then-write would let the reader see
            # a half-written file and fail for a reason that is not the one under test.
            while not stop.is_set():
                for mode in ("observe", "enforce"):
                    self._write(staged, mode)
                    os.replace(staged, p)

        writer = threading.Thread(target=churn, daemon=True)
        writer.start()
        try:
            for _ in range(500):
                assert api._load_agent_policy(str(p), "prod").mode in ("observe", "enforce")
        finally:
            stop.set()
            writer.join(timeout=5)

        self._write(p, "enforce")
        for _ in range(20):
            assert api._load_agent_policy(str(p), "prod").mode == "enforce"

    def test_missing_file_still_raises(self, tmp_path):
        from jataayu import api

        with pytest.raises(FileNotFoundError):
            api._load_agent_policy(str(tmp_path / "nope.yml"), "prod")


class TestScalarListFieldsAreRejected:
    """`forbidden_capabilities: exec` is a scalar. list("exec") is ['e','x','e','c'],
    which forbids nothing — a fail-open that no other validation catches."""

    def _load(self, text, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(text)
        return load_policy(str(p))

    def test_scalar_forbidden_capabilities_on_an_agent_raises(self, tmp_path):
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            self._load(
                "version: 1\nagents:\n  prod:\n    forbidden_capabilities: exec\n", tmp_path
            )

    def test_scalar_forbidden_capabilities_in_defaults_raises(self, tmp_path):
        """No `agents:` block — the defaults block has to be validated on its own.

        With an agent present the scalar was only caught because _parse_agent inherited
        it; a policy that is nothing but `defaults:` was parsed clean and blew up later
        on every authorization request instead.
        """
        with pytest.raises(ValueError, match="defaults"):
            self._load(
                "version: 1\ndefaults:\n  forbidden_capabilities: exec\n", tmp_path
            )

    def test_scalar_in_defaults_raises_from_from_dict_directly(self):
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            PolicyLoader.from_dict(
                {"version": 1, "defaults": {"forbidden_capabilities": "exec"}}
            )

    @pytest.mark.parametrize(
        "key",
        ["forbidden_capabilities", "allowed_capabilities",
         "internal_codenames", "gtm_codenames"],
    )
    def test_every_inherited_list_key_is_validated_in_defaults(self, key):
        with pytest.raises(ValueError, match=key):
            PolicyLoader.from_dict({"version": 1, "defaults": {key: "oops"}})

    def test_non_string_elements_are_rejected(self, tmp_path):
        """`[1, 2]` is a list, so the container check passes — but is_capability_allowed()
        compares against a str and can never match, so it forbids nothing."""
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            self._load(
                "version: 1\nagents:\n  prod:\n    forbidden_capabilities: [1, 2]\n",
                tmp_path,
            )

    def test_non_string_elements_in_defaults_are_rejected(self):
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            PolicyLoader.from_dict(
                {"version": 1, "defaults": {"forbidden_capabilities": [1, 2]}}
            )

    def test_scalar_in_defaults_raises_on_the_fallback_path_too(self):
        """get_agent_policy() is reachable without the loader — the same rule applies."""
        policy = Policy(defaults={"forbidden_capabilities": "exec"})
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            policy.get_agent_policy("unknown")

    @pytest.mark.parametrize("agent", [None, "prod", "prodd"])
    def test_a_scalar_never_silently_shreds_into_characters(self, tmp_path, agent):
        """The failure this replaces: named agent denied, typo'd agent allowed."""
        from jataayu import jataayu_authorize_action

        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            "version: 1\ndefaults:\n  forbidden_capabilities: exec\nagents:\n  prod: {}\n"
        )
        with pytest.raises(ValueError):
            jataayu_authorize_action(
                "shell.exec", {"command": "ls"}, untrusted=False,
                policy_file=str(p), agent=agent,
            )

    def test_scalar_allowed_surfaces_raises(self, tmp_path):
        with pytest.raises(ValueError, match="allowed_surfaces"):
            self._load(
                "version: 1\nagents:\n  prod:\n    allowed_surfaces: internal\n", tmp_path
            )

    def test_a_real_list_still_loads(self, tmp_path):
        p = self._load(
            "version: 1\nagents:\n  prod:\n    forbidden_capabilities: [exec]\n", tmp_path
        )
        assert p.get_agent_policy("prod").forbidden_capabilities == ["exec"]


class TestDefaultsFallbackInheritsEverything:
    """A misspelled agent name must not silently drop half the `defaults:` block.

    get_agent_policy()'s unknown-agent branch and PolicyLoader._parse_agent() are the
    two ways an AgentPolicy comes into being; any field one inherits and the other does
    not is a policy that turns off when you typo the agent name.
    """

    POLICY = (
        "version: 1\n"
        "defaults:\n"
        "  internal_codenames: [Skunkworks]\n"
        "  gtm_codenames: [Skylark]\n"
        "  forbidden_capabilities: [exec]\n"
        "  check_credentials: false\n"
        "  check_high_entropy: true\n"
        "  block_threshold: 0.5\n"
        "  llm_threshold: 0.1\n"
        "  strict_unknown_tools: true\n"
        "  mode: observe\n"
        "  tool_effects:\n    internal.run_playbook: shell\n"
        "agents:\n  prod: {}\n"
    )

    @pytest.fixture
    def policy(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(self.POLICY)
        return load_policy(str(p))

    def test_the_typo_path_matches_the_named_path_field_for_field(self, policy):
        named = policy.get_agent_policy("prod").to_dict()
        typo = policy.get_agent_policy("prodd").to_dict()
        named.pop("name"), typo.pop("name")
        assert named == typo

    def test_codenames_are_inherited_on_the_fallback_path(self, policy):
        assert policy.get_agent_policy("prodd").internal_codenames == ["Skunkworks"]
        assert policy.get_agent_policy("prodd").gtm_codenames == ["Skylark"]

    @pytest.mark.parametrize("agent", ["prod", "prodd", ""])
    def test_a_codename_is_blocked_whatever_the_agent_name(self, policy, agent):
        """The live failure: agent='prod' blocked, agent='prodd' clean at risk 0.0."""
        from jataayu.guards.outbound import OutboundGuard

        guard = OutboundGuard(policy.get_agent_policy(agent).to_privacy_config())
        result = guard.check("Ship notes for Skunkworks.", surface="github-issue")
        assert not result.is_safe

    def test_the_fallback_lists_are_not_aliased_to_defaults(self, policy):
        got = policy.get_agent_policy("prodd")
        assert got.internal_codenames is not policy.defaults["internal_codenames"]
        got.internal_codenames.clear()
        assert policy.defaults["internal_codenames"] == ["Skunkworks"]


class TestFromDirRejectsANonMapping:
    def test_a_list_valued_yaml_file_raises_valueerror(self, tmp_path):
        """Without the guard this is an AttributeError from raw.get(), which reads as a
        Jataayu bug rather than as the user's malformed policy file."""
        d = tmp_path / "policy.d"
        d.mkdir()
        (d / "a.yml").write_text("- version: 1\n- agents: {}\n")
        with pytest.raises(ValueError, match="mapping"):
            PolicyLoader.from_dir(str(d))


class TestPolicyListsAreNotAliased:
    """Policies are cached and long-lived, and to_dict()/to_privacy_config() hand these
    lists out past the module boundary — one caller's mutation must not poison the rest."""

    @pytest.fixture
    def policy(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            "version: 1\n"
            "defaults:\n  forbidden_capabilities: [exec]\n"
            "agents:\n  a: {}\n  b: {}\n"
        )
        return load_policy(str(p))

    def test_a_named_agent_does_not_alias_the_defaults_list(self, policy):
        agent = policy.agents["a"]
        assert agent.forbidden_capabilities is not policy.defaults["forbidden_capabilities"]

    def test_two_agents_do_not_share_one_list(self, policy):
        assert policy.agents["a"].forbidden_capabilities is not (
            policy.agents["b"].forbidden_capabilities
        )

    def test_mutating_one_agent_leaves_the_others_intact(self, policy):
        policy.agents["a"].forbidden_capabilities.clear()
        assert policy.agents["b"].forbidden_capabilities == ["exec"]
        assert policy.defaults["forbidden_capabilities"] == ["exec"]
        assert policy.get_agent_policy("unknown").forbidden_capabilities == ["exec"]

    def test_inherited_codenames_are_not_aliased(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            "version: 1\n"
            "defaults:\n  internal_codenames: [Bluebird]\n"
            "agents:\n  a: {}\n  b: {}\n"
        )
        policy = load_policy(str(p))
        policy.agents["a"].to_privacy_config().internal_codenames.append("Leaked")
        assert policy.agents["b"].internal_codenames == ["Bluebird"]


class TestEmptyBodiesRaiseAClearError:
    def test_empty_agents_body_in_a_directory_loads(self, tmp_path):
        """`agents:` with no body is zero agents, exactly as from_dict already treats it —
        not an opaque AttributeError from .items() on None."""
        (tmp_path / "a.yml").write_text("version: 1\nagents:\n")
        assert load_policy(str(tmp_path)).list_agents() == []

    def test_empty_agent_body_in_a_directory(self, tmp_path):
        (tmp_path / "a.yml").write_text("version: 1\nagents:\n  prod:\n")
        with pytest.raises(ValueError, match="agents.prod"):
            load_policy(str(tmp_path))

    def test_empty_defaults_body(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\ndefaults:\n")
        assert load_policy(str(p)).get_agent_policy("anyone").mode == "enforce"

    def test_a_top_level_list_raises(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text("- version: 1\n")
        with pytest.raises(ValueError, match="mapping"):
            load_policy(str(p))


class TestSectionsMustBeMappings:
    """`agents:` written as a YAML sequence must name the offending key.

    Both loader entry points are covered because they kept diverging: from_dir() merges
    this section itself, so a check added to from_dict() alone never ran for a
    directory load. Three review rounds found this same shape; these tests are what
    keeps the fourth from finding it again. `surfaces:` is no longer a section — any
    shape of it raises; see TestSurfacesBlockIsRejected.
    """

    def test_from_dict_rejects_a_sequence(self):
        with pytest.raises(ValueError, match="agents: expected a mapping"):
            PolicyLoader.from_dict({"version": 1, "agents": ["prod"]})

    def test_from_dir_rejects_a_sequence_and_names_the_file(self, tmp_path):
        (tmp_path / "bad.yml").write_text("version: 1\nagents:\n  - prod\n")
        with pytest.raises(ValueError, match=r"bad\.yml: agents: expected a mapping"):
            load_policy(str(tmp_path))

    def test_defaults_as_a_sequence_still_raises(self):
        with pytest.raises(ValueError, match="defaults: expected a mapping"):
            PolicyLoader.from_dict({"version": 1, "defaults": ["x"]})


class TestSurfacesBlockIsRejected:
    """A `surfaces:` block used to parse into Policy.global_surface_overrides and then
    be read by nobody: InboundGuard resolves a surface through
    JataayuEngine.get_surface_profile(), which reads SURFACE_PROFILES directly. A user
    could set risk_multiplier: 0.001 on github-issue, load clean, and change nothing.
    """

    SURFACES_YAML = (
        "version: 1\n"
        "surfaces:\n"
        "  github-issue:\n"
        "    trust_level: high\n"
        "    inbound_strict: false\n"
        "    risk_multiplier: 0.001\n"
    )

    def _assert_message(self, excinfo):
        msg = str(excinfo.value)
        assert "not policy-tunable" in msg
        assert "jataayu/surfaces/profiles.py" in msg

    def test_from_dict_raises(self):
        with pytest.raises(ValueError) as e:
            PolicyLoader.from_dict({"version": 1, "surfaces": {"github-issue": {}}})
        self._assert_message(e)

    def test_from_file_raises(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(self.SURFACES_YAML)
        with pytest.raises(ValueError) as e:
            load_policy(str(p))
        self._assert_message(e)

    def test_from_dir_raises_and_names_the_file(self, tmp_path):
        (tmp_path / "10-surfaces.yml").write_text(self.SURFACES_YAML)
        with pytest.raises(ValueError) as e:
            load_policy(str(tmp_path))
        assert "10-surfaces.yml" in str(e.value)
        self._assert_message(e)

    @pytest.mark.parametrize("body", [None, [], ["github-issue"], "github-issue", {}])
    def test_any_shape_of_the_key_raises(self, body):
        """Including an empty body — `surfaces:` alone is still a user asking for
        something the loader cannot give them, so it gets the explanation too."""
        with pytest.raises(ValueError) as e:
            PolicyLoader.from_dict({"version": 1, "surfaces": body})
        self._assert_message(e)

    def test_agent_surface_overrides_still_parse(self, tmp_path):
        """The per-agent form still parses and is reachable on AgentPolicy. NOTE: no
        guard reads it either — see the dead-key audit; it is not fixed here."""
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            "version: 1\n"
            "agents:\n"
            "  bot:\n"
            "    surface_overrides:\n"
            "      github-issue:\n"
            "        block_threshold: 0.65\n"
        )
        agent = load_policy(str(p)).get_agent_policy("bot")
        assert agent.get_block_threshold("github-issue") == 0.65

    def test_builtin_profiles_are_unchanged_by_any_policy(self, tmp_path):
        """The guards read SURFACE_PROFILES, and no policy load perturbs it."""
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        from jataayu.guards.inbound import InboundGuard

        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  bot:\n    block_threshold: 0.1\n")
        load_policy(str(p))
        assert SURFACE_PROFILES["github-issue"]["risk_multiplier"] == 1.2
        assert SURFACE_PROFILES["github-issue"]["trust_level"] == "low"
        assert InboundGuard().get_surface_profile("github-issue") == SURFACE_PROFILES["github-issue"]


class TestShippedExampleLoads:
    """examples/jataayu-policy.example.yml is what users copy. If it documents a key
    the loader rejects — or one it ignores — they find out the hard way."""

    EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "jataayu-policy.example.yml"

    def test_example_file_exists(self):
        assert self.EXAMPLE.is_file(), f"missing {self.EXAMPLE}"

    def test_example_loads_cleanly(self):
        policy = load_policy(str(self.EXAMPLE))
        assert "coding-agent" in policy.list_agents()
        assert policy.get_agent_policy("prod-agent").mode == "observe"

    def test_example_documents_no_surfaces_block(self):
        """A regression guard on the doc itself, not just the loader."""
        import yaml
        assert "surfaces" not in yaml.safe_load(self.EXAMPLE.read_text())


class TestBoolFieldsAreNotCoerced:
    """`strict_unknown_tools: "false"` must raise, not evaluate to True.

    bool("false") is True, so the quoted form silently turns the switch ON — the same
    "reinterprets what you wrote" failure this loader rejects for scalars elsewhere.
    """

    def test_quoted_false_on_an_agent_raises(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text('version: 1\nagents:\n  prod:\n    strict_unknown_tools: "false"\n')
        with pytest.raises(ValueError, match="agents.prod: strict_unknown_tools must be true or false"):
            load_policy(str(p))

    def test_quoted_false_in_defaults_raises_at_load(self, tmp_path):
        """Named `defaults`, and raised at load — not deferred to the first unknown agent."""
        p = tmp_path / "jataayu-policy.yml"
        p.write_text('version: 1\ndefaults:\n  strict_unknown_tools: "false"\n')
        with pytest.raises(ValueError, match="defaults: strict_unknown_tools must be true or false"):
            load_policy(str(p))

    def test_an_int_is_not_a_bool(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  prod:\n    strict_unknown_tools: 1\n")
        with pytest.raises(ValueError, match="strict_unknown_tools must be true or false"):
            load_policy(str(p))

    def test_real_bools_still_load(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  prod:\n    strict_unknown_tools: true\n  dev: {}\n")
        policy = load_policy(str(p))
        assert policy.get_agent_policy("prod").strict_unknown_tools is True
        assert policy.get_agent_policy("dev").strict_unknown_tools is False
