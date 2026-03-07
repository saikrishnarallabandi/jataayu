"""
Tests for Issue #6 — YAML policy configuration.
"""
import os
import tempfile
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
      - Veda
      - Tarak
    check_credentials: false

surfaces:
  github-issue:
    trust_level: low
    inbound_strict: true
    risk_multiplier: 1.3
  coding-task:
    trust_level: medium
    inbound_strict: false
    risk_multiplier: 0.7
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

    def test_simple_yaml_parser_handles_inline_lists_and_scalars(self):
        raw = PolicyLoader._parse_simple_yaml(
            """
version: 1
agents:
  bot:
    allowed_surfaces: [internal, github-issue]
    check_credentials: false
"""
        )
        assert raw["version"] == 1
        assert raw["agents"]["bot"]["allowed_surfaces"] == ["internal", "github-issue"]
        assert raw["agents"]["bot"]["check_credentials"] is False


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
    def test_global_surface_override(self, policy):
        """Global surface overrides should affect get_surface_profile."""
        profile = policy.get_surface_profile("github-issue")
        # Should reflect the global surface override (risk_multiplier: 1.3)
        assert profile.get("risk_multiplier", 0) == 1.3

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
