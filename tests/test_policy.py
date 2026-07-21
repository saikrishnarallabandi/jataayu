"""
Tests for Issue #6 — YAML policy configuration.
"""

import os
import tempfile
from pathlib import Path

import pytest
from jataayu.config.policy import (
    Policy,
    PolicyLoader,
    load_policy,
    AgentPolicy,
    SUPPORTED_POLICY_VERSIONS,
    _DEAD_KEYS,
    _INHERITED_BOOL_KEYS,
    _INHERITED_LIST_KEYS,
)
from jataayu.core.errors import UnknownAgentError


# ---------------------------------------------------------------------------
# Sample YAML policy content
# ---------------------------------------------------------------------------

SAMPLE_POLICY_YAML = """
version: 1

defaults:
  check_credentials: true
  check_high_entropy: false

agents:
  coding-agent:
    protected_names: []
    check_credentials: false

  github-bot:
    protected_names:
      - "Alice Smith"
      - "Bob Jones"
    check_credentials: true

  privacy-bot:
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
            "defaults": {"check_credentials": False},
            "agents": {
                "test-agent": {
                    "protected_names": ["Alice"],
                }
            },
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
    protected_names: [Alice]
""")
        p2 = tmp_path / "more-agents.yml"
        p2.write_text("""
version: 1
agents:
  agent-b:
    protected_names: [Bob]
""")
        policy = PolicyLoader.from_dir(tmp_path)
        assert "agent-a" in policy.agents
        assert "agent-b" in policy.agents


class TestAgentPolicy:
    def test_unknown_agent_raises(self, policy):
        """Naming an agent asserts it exists. A typo must not resolve to anything."""
        with pytest.raises(UnknownAgentError, match="nonexistent-agent"):
            policy.get_agent_policy("nonexistent-agent")

    def test_the_error_lists_the_agents_that_do_exist(self, policy):
        with pytest.raises(UnknownAgentError, match="github-bot"):
            policy.get_agent_policy("github-bott")

    def test_no_agent_returns_defaults(self, policy):
        agent = policy.get_agent_policy("")
        assert agent.name == ""
        assert agent.check_credentials is True  # from defaults

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


class TestToPrivacyConfig:
    def test_to_privacy_config_protected_names(self, policy):
        agent = policy.get_agent_policy("github-bot")
        config = agent.to_privacy_config()
        assert "Alice Smith" in config.protected_names

    def test_to_privacy_config_credentials(self, policy):
        agent = policy.get_agent_policy("coding-agent")
        config = agent.to_privacy_config()
        assert config.check_credentials is False

    def test_to_privacy_config_leaves_thresholds_at_privacyconfig_defaults(self, policy):
        """No policy key can move them, so they must come from PrivacyConfig itself."""
        from jataayu.guards.outbound import PrivacyConfig

        config = policy.get_agent_policy("github-bot").to_privacy_config()
        assert config.block_threshold == PrivacyConfig.block_threshold
        assert config.llm_threshold == PrivacyConfig.llm_threshold
        assert config.use_llm == PrivacyConfig.use_llm


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
        assert "protected_names" in d
        assert "forbidden_capabilities" in d
        # A rejected key must not reappear on the way out.
        assert not (_DEAD_KEYS.keys() & d.keys())


class TestDefaultPolicy:
    def test_default_policy_has_safe_defaults(self):
        p = load_policy()
        agent = p.get_agent_policy("")
        assert agent.check_credentials is True
        assert agent.mode == "enforce"

    def test_default_policy_names_no_rejected_key(self):
        """load_policy()'s built-in defaults are fed back through _parse_agent, so a
        rejected key in there would make the no-file path raise on itself."""
        p = load_policy()
        assert not (_DEAD_KEYS.keys() & p.defaults.keys())

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
  check_credentials: false

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
            EffectBoundary,
            Value,
            Provenance,
            EffectClass,
            Decision,
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
        b = EffectBoundary(policy=agent, mode="enforce")  # isolate strict from observe
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

        assert b.classify("local.tool") is EffectClass.SHELL  # from the kwarg
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
            "internal.run_playbook",
            {"x": 1},
            policy_file=effect_policy_file,
            agent="prod",
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
            self._load("version: 1\nagents:\n  prod:\n    tool_effects:\n      db.query: shel\n")

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
    "version: 1\ndefaults:\n  forbidden_capabilities: [exec, fs_write]\nagents:\n  prod: {}\n"
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
            "exec",
            "fs_write",
        ]

    @pytest.mark.parametrize("agent", [None, "prod"])
    def test_shell_denies_with_or_without_a_matching_agent(self, policy_path, agent):
        """Named and unnamed both deny — unnamed inherits the forbidding defaults."""
        from jataayu import jataayu_authorize_action

        d = jataayu_authorize_action(
            "shell.exec",
            {"command": "ls"},
            untrusted=False,
            policy_file=policy_path,
            agent=agent,
        )
        assert d["decision"] == "deny"
        assert "exec" in d["violations"]

    def test_a_typod_agent_raises_rather_than_inheriting(self, policy_path):
        """`defaults:` is a floor, not a substitute: inheriting it would still shed
        everything the named agent's own block forbade."""
        from jataayu import jataayu_authorize_action

        with pytest.raises(UnknownAgentError, match="prodd"):
            jataayu_authorize_action(
                "shell.exec",
                {"command": "ls"},
                untrusted=False,
                policy_file=policy_path,
                agent="prodd",
            )

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
            "internal.run_playbook",
            {"x": 1},
            policy_file=str(p),
            agent="prod",
        )
        assert first["decision"] == "allow"
        assert first["would_decision"] == "deny"

        self._write(p, "enforce")
        after = jataayu_authorize_action(
            "internal.run_playbook",
            {"x": 1},
            policy_file=str(p),
            agent="prod",
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
        assert (
            jataayu_authorize_action(
                "internal.run_playbook",
                {"x": 1},
                policy_file=str(p),
                agent="prod",
            )["decision"]
            == "allow"
        )

        self._write(p, "enforce")
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        assert p.stat().st_mtime_ns == st.st_mtime_ns
        assert p.stat().st_size == st.st_size

        for _ in range(2):  # ...and stays enforcing, not just on the first re-read
            assert (
                jataayu_authorize_action(
                    "internal.run_playbook",
                    {"x": 1},
                    policy_file=str(p),
                    agent="prod",
                )["decision"]
                == "deny"
            )

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
        assert (
            jataayu_authorize_action(
                "shell.exec",
                {"x": 1},
                untrusted=False,
                policy_file=str(p),
                agent="prod",
            )["decision"]
            == "allow"
        )

        p.write_text("version: 1\nagents:\n  prod:\n    forbidden_capabilities: [exec]\n")
        assert (
            jataayu_authorize_action(
                "shell.exec",
                {"x": 1},
                untrusted=False,
                policy_file=str(p),
                agent="prod",
            )["decision"]
            == "deny"
        )

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
            policy_mod.PolicyLoader,
            "_load_yaml",
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
            self._load("version: 1\nagents:\n  prod:\n    forbidden_capabilities: exec\n", tmp_path)

    def test_scalar_forbidden_capabilities_in_defaults_raises(self, tmp_path):
        """No `agents:` block — the defaults block has to be validated on its own.

        With an agent present the scalar was only caught because _parse_agent inherited
        it; a policy that is nothing but `defaults:` was parsed clean and blew up later
        on every authorization request instead.
        """
        with pytest.raises(ValueError, match="defaults"):
            self._load("version: 1\ndefaults:\n  forbidden_capabilities: exec\n", tmp_path)

    def test_scalar_in_defaults_raises_from_from_dict_directly(self):
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            PolicyLoader.from_dict({"version": 1, "defaults": {"forbidden_capabilities": "exec"}})

    @pytest.mark.parametrize("key", _INHERITED_LIST_KEYS)
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
            PolicyLoader.from_dict({"version": 1, "defaults": {"forbidden_capabilities": [1, 2]}})

    def test_scalar_in_defaults_raises_on_the_fallback_path_too(self):
        """get_agent_policy() is reachable without the loader — the same rule applies."""
        policy = Policy(defaults={"forbidden_capabilities": "exec"})
        with pytest.raises(ValueError, match="forbidden_capabilities"):
            policy.get_agent_policy("")

    @pytest.mark.parametrize("agent", [None, "prod", "prodd"])
    def test_a_scalar_never_silently_shreds_into_characters(self, tmp_path, agent):
        """The failure this replaces: named agent denied, typo'd agent allowed."""
        from jataayu import jataayu_authorize_action

        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\ndefaults:\n  forbidden_capabilities: exec\nagents:\n  prod: {}\n")
        with pytest.raises(ValueError):
            jataayu_authorize_action(
                "shell.exec",
                {"command": "ls"},
                untrusted=False,
                policy_file=str(p),
                agent=agent,
            )

    def test_scalar_protected_names_raises(self, tmp_path):
        with pytest.raises(ValueError, match="protected_names"):
            self._load("version: 1\nagents:\n  prod:\n    protected_names: Alice\n", tmp_path)

    def test_a_real_list_still_loads(self, tmp_path):
        p = self._load(
            "version: 1\nagents:\n  prod:\n    forbidden_capabilities: [exec]\n", tmp_path
        )
        assert p.get_agent_policy("prod").forbidden_capabilities == ["exec"]


class TestDefaultsFallbackInheritsEverything:
    """A call naming no agent must not silently drop half the `defaults:` block.

    get_agent_policy()'s no-agent branch and PolicyLoader._parse_agent() are the two
    ways an AgentPolicy comes into being; any field one inherits and the other does not
    is a policy that turns off when you omit the agent name. (A *misspelled* name takes
    neither path — it raises; see test_a_typod_name_raises_instead.)
    """

    POLICY = (
        "version: 1\n"
        "defaults:\n"
        "  internal_codenames: [Skunkworks]\n"
        "  gtm_codenames: [Skylark]\n"
        "  forbidden_capabilities: [exec]\n"
        "  check_credentials: false\n"
        "  check_high_entropy: true\n"
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

    def test_the_no_agent_path_matches_the_named_path_field_for_field(self, policy):
        named = policy.get_agent_policy("prod").to_dict()
        unnamed = policy.get_agent_policy("").to_dict()
        named.pop("name"), unnamed.pop("name")
        assert named == unnamed

    def test_codenames_are_inherited_on_the_fallback_path(self, policy):
        assert policy.get_agent_policy("").internal_codenames == ["Skunkworks"]
        assert policy.get_agent_policy("").gtm_codenames == ["Skylark"]

    def test_a_typod_name_raises_instead(self, policy):
        with pytest.raises(UnknownAgentError, match="prodd"):
            policy.get_agent_policy("prodd")

    @pytest.mark.parametrize("agent", ["prod", ""])
    def test_a_codename_is_blocked_whatever_the_agent_name(self, policy, agent):
        """The live failure: agent='prod' blocked, agent='' clean at risk 0.0."""
        from jataayu.guards.outbound import OutboundGuard

        guard = OutboundGuard(policy.get_agent_policy(agent).to_privacy_config())
        result = guard.check("Ship notes for Skunkworks.", surface="github-issue")
        assert not result.is_safe

    def test_the_fallback_lists_are_not_aliased_to_defaults(self, policy):
        got = policy.get_agent_policy("")
        assert got.internal_codenames is not policy.defaults["internal_codenames"]
        got.internal_codenames.clear()
        assert policy.defaults["internal_codenames"] == ["Skunkworks"]


class TestEveryInheritedKeyActuallyInherits:
    """Every key on _INHERITED_LIST_KEYS / _INHERITED_BOOL_KEYS must resolve from
    `defaults:` on BOTH paths an AgentPolicy is reached by.

    Parametrized off the tuples themselves, deliberately. The predecessor of this class
    hand-listed its keys and every case used `internal_codenames` — so
    `protected_names` and `disabled_cred_rules` were resolved off the agent block alone,
    a roster written in `defaults:` reached the wire unredacted, and a 16-test suite was
    green. A test that names its own keys cannot catch the field nobody remembered.
    """

    # "" is the no-agent call, "prod" the named one. A typo is not a third path — it
    # raises (TestDefaultsFallbackInheritsEverything::test_a_typod_name_raises_instead).
    AGENTS = ["", "prod"]

    @pytest.mark.parametrize("agent", AGENTS)
    @pytest.mark.parametrize("key", _INHERITED_LIST_KEYS)
    def test_list_key_inherits_from_defaults(self, tmp_path, key, agent):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f"version: 1\ndefaults:\n  {key}: [zephyr]\nagents:\n  prod: {{}}\n")
        got = load_policy(str(p)).get_agent_policy(agent)
        assert getattr(got, key) == ["zephyr"], f"{key} did not inherit for agent={agent!r}"

    @pytest.mark.parametrize("agent", AGENTS)
    @pytest.mark.parametrize("key", _INHERITED_BOOL_KEYS)
    def test_bool_key_inherits_from_defaults(self, tmp_path, key, agent):
        """Asserted against the OPPOSITE of the built-in default, so a field that ignores
        `defaults:` and falls through to its hardcoded value fails here."""
        builtin = getattr(AgentPolicy(name="x"), key)
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            f"version: 1\ndefaults:\n  {key}: {str(not builtin).lower()}\nagents:\n  prod: {{}}\n"
        )
        got = load_policy(str(p)).get_agent_policy(agent)
        assert getattr(got, key) is (not builtin), f"{key} did not inherit for agent={agent!r}"

    @pytest.mark.parametrize("agent", AGENTS)
    @pytest.mark.parametrize("key", _INHERITED_LIST_KEYS)
    def test_the_agent_block_still_wins_over_defaults(self, tmp_path, key, agent):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            f"version: 1\ndefaults:\n  {key}: [zephyr]\nagents:\n  prod:\n    {key}: [tern]\n"
        )
        expected = ["tern"] if agent == "prod" else ["zephyr"]
        assert getattr(load_policy(str(p)).get_agent_policy(agent), key) == expected

    @pytest.mark.parametrize("key", _INHERITED_LIST_KEYS)
    def test_an_inherited_list_is_never_aliased_to_defaults(self, tmp_path, key):
        """A copy per agent — one caller's mutation must not poison the next."""
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f"version: 1\ndefaults:\n  {key}: [zephyr]\nagents:\n  prod: {{}}\n")
        policy = load_policy(str(p))
        got = getattr(policy.get_agent_policy("prod"), key)
        assert got is not policy.defaults[key]
        got.clear()
        assert policy.defaults[key] == ["zephyr"]

    def test_every_list_field_on_agentpolicy_is_covered(self):
        """The tuples are the spec, so they must not silently fall behind the dataclass.

        Every list/bool field on AgentPolicy must be on a tuple above.
        """
        import dataclasses

        listy, booly = set(), set()
        for f in dataclasses.fields(AgentPolicy):
            if f.name in ("name", "tool_effects", "extra"):
                continue
            value = getattr(AgentPolicy(name="x"), f.name)
            (listy if isinstance(value, list) else booly if isinstance(value, bool) else set()).add(
                f.name
            )
        assert listy == set(_INHERITED_LIST_KEYS)
        assert booly == set(_INHERITED_BOOL_KEYS)


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
            "version: 1\ndefaults:\n  forbidden_capabilities: [exec]\nagents:\n  a: {}\n  b: {}\n"
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
        assert policy.get_agent_policy("").forbidden_capabilities == ["exec"]

    def test_inherited_codenames_are_not_aliased(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            "version: 1\ndefaults:\n  internal_codenames: [Bluebird]\nagents:\n  a: {}\n  b: {}\n"
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
        assert load_policy(str(p)).get_agent_policy("").mode == "enforce"

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

    def test_builtin_profiles_are_unchanged_by_any_policy(self, tmp_path):
        """The guards read SURFACE_PROFILES, and no policy load perturbs it."""
        from jataayu.surfaces.profiles import SURFACE_PROFILES
        from jataayu.guards.inbound import InboundGuard

        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  bot:\n    check_credentials: false\n")
        load_policy(str(p))
        assert SURFACE_PROFILES["github-issue"]["risk_multiplier"] == 1.2
        assert SURFACE_PROFILES["github-issue"]["trust_level"] == "low"
        assert (
            InboundGuard().get_surface_profile("github-issue") == SURFACE_PROFILES["github-issue"]
        )


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


class TestDeadKeysAreRejected:
    """A key no guard reads must raise at load, not parse into an ignored field.

    `block_threshold: 0.3` under an agent used to load clean, land on AgentPolicy, and
    change nothing — the user believed they had tightened a security threshold. Every
    key in _DEAD_KEYS is parametrized from the module rather than listed here: this
    branch already shipped a bug that survived because a test enumerated keys by hand.
    """

    # A body for each key that is structurally valid, so the rejection is about the key
    # existing at all and not about its shape.
    BODIES = {
        "block_threshold": "0.3",
        "llm_threshold": "0.1",
        "use_llm": "true",
        "allowed_surfaces": "[internal]",
        "surface_overrides": "\n      github-issue:\n        block_threshold: 0.65",
    }

    def _assert_actionable(self, excinfo, key):
        msg = str(excinfo.value)
        assert key in msg
        assert "Remove the key" in msg
        # It must say what to do instead, not merely that it is unsupported.
        assert any(s in msg for s in ("argument", "profiles.py")), msg

    def test_every_dead_key_has_a_body(self):
        """Keeps BODIES from falling behind _DEAD_KEYS."""
        assert set(self.BODIES) == set(_DEAD_KEYS)

    @pytest.mark.parametrize("key", sorted(_DEAD_KEYS))
    def test_on_a_named_agent_raises(self, tmp_path, key):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f"version: 1\nagents:\n  prod:\n    {key}: {self.BODIES[key]}\n")
        with pytest.raises(ValueError) as e:
            load_policy(str(p))
        assert "agents.prod" in str(e.value)
        self._assert_actionable(e, key)

    @pytest.mark.parametrize("key", sorted(_DEAD_KEYS))
    def test_in_defaults_raises_at_load(self, tmp_path, key):
        """At load — not deferred to the first call that resolves an unknown agent."""
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f"version: 1\ndefaults:\n  {key}: {self.BODIES[key]}\n")
        with pytest.raises(ValueError) as e:
            load_policy(str(p))
        assert "defaults" in str(e.value)
        self._assert_actionable(e, key)

    @pytest.mark.parametrize("key", sorted(_DEAD_KEYS))
    def test_from_dir_raises_too(self, tmp_path, key):
        """from_dir merges agent blocks itself; it must not route around the check."""
        (tmp_path / "10-agents.yml").write_text(
            f"version: 1\nagents:\n  prod:\n    {key}: {self.BODIES[key]}\n"
        )
        with pytest.raises(ValueError) as e:
            load_policy(str(tmp_path))
        self._assert_actionable(e, key)

    @pytest.mark.parametrize("key", sorted(_DEAD_KEYS))
    def test_from_dict_raises_too(self, key):
        with pytest.raises(ValueError) as e:
            PolicyLoader.from_dict({"version": 1, "agents": {"prod": {key: None}}})
        self._assert_actionable(e, key)

    @pytest.mark.parametrize("key", sorted(_DEAD_KEYS))
    def test_the_key_is_not_a_field_on_agentpolicy(self, key):
        """Rejected at parse AND gone from the dataclass — a field nothing populates
        would still answer a caller, with a default that is a lie."""
        assert not hasattr(AgentPolicy(name="x"), key)

    @pytest.mark.parametrize("key", sorted(_DEAD_KEYS))
    def test_it_does_not_land_in_extra(self, key):
        """`extra` is the catch-all for unknown keys; a dead key must raise first."""
        with pytest.raises(ValueError):
            PolicyLoader.from_dict({"version": 1, "agents": {"prod": {key: 0.3}}})

    def test_a_policy_without_them_still_loads(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(
            "version: 1\ndefaults:\n  check_credentials: true\n"
            "agents:\n  prod:\n    forbidden_capabilities: [exec]\n"
        )
        assert load_policy(str(p)).get_agent_policy("prod").check_credentials is True


class TestVersionIsValidated:
    """`version:` was stored on Policy and never compared to anything, so `version: 7`
    — a file written against a format this build does not implement — loaded clean."""

    def test_the_supported_version_loads(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  prod: {}\n")
        assert load_policy(str(p)).version == 1

    def test_an_omitted_version_defaults_to_supported(self):
        assert PolicyLoader.from_dict({"agents": {}}).version == 1

    @pytest.mark.parametrize("bad", [0, 2, 7, -1, "1", 1.0, True, None])
    def test_an_unsupported_version_raises(self, bad):
        with pytest.raises(ValueError, match="unsupported policy version"):
            PolicyLoader.from_dict({"version": bad, "agents": {}})

    def test_from_dir_names_the_offending_file(self, tmp_path):
        """from_dir synthesizes its own version for the merged dict, so a bad one in an
        individual file would otherwise never be checked."""
        (tmp_path / "10-bad.yml").write_text("version: 99\nagents:\n  prod: {}\n")
        with pytest.raises(ValueError, match="unsupported policy version"):
            load_policy(str(tmp_path))

    def test_supported_versions_is_not_empty(self):
        assert SUPPORTED_POLICY_VERSIONS


class TestBoolFieldsAreNotCoerced:
    """`strict_unknown_tools: "false"` must raise, not evaluate to True.

    bool("false") is True, so the quoted form silently turns the switch ON — the same
    "reinterprets what you wrote" failure this loader rejects for scalars elsewhere.
    """

    @pytest.mark.parametrize("key", _INHERITED_BOOL_KEYS)
    def test_quoted_false_on_an_agent_raises(self, tmp_path, key):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f'version: 1\nagents:\n  prod:\n    {key}: "false"\n')
        with pytest.raises(ValueError, match=f"agents.prod: {key} must be true or false"):
            load_policy(str(p))

    @pytest.mark.parametrize("key", _INHERITED_BOOL_KEYS)
    def test_quoted_false_in_defaults_raises_at_load(self, tmp_path, key):
        """Named `defaults`, and raised at load — not deferred to the first unknown agent."""
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f'version: 1\ndefaults:\n  {key}: "false"\n')
        with pytest.raises(ValueError, match=f"defaults: {key} must be true or false"):
            load_policy(str(p))

    @pytest.mark.parametrize("key", _INHERITED_BOOL_KEYS)
    def test_an_int_is_not_a_bool(self, tmp_path, key):
        """`check_credentials: 0` silently switched off the entire credential scan."""
        p = tmp_path / "jataayu-policy.yml"
        p.write_text(f"version: 1\nagents:\n  prod:\n    {key}: 0\n")
        with pytest.raises(ValueError, match=f"{key} must be true or false"):
            load_policy(str(p))

    def test_real_bools_still_load(self, tmp_path):
        p = tmp_path / "jataayu-policy.yml"
        p.write_text("version: 1\nagents:\n  prod:\n    strict_unknown_tools: true\n  dev: {}\n")
        policy = load_policy(str(p))
        assert policy.get_agent_policy("prod").strict_unknown_tools is True
        assert policy.get_agent_policy("dev").strict_unknown_tools is False
