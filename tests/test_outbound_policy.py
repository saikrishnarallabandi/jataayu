"""The outbound half of the policy format must actually reach the guard.

`jataayu_check_outbound` read ZERO policy fields: a user wrote `protected_names: [Alice]`,
it parsed clean, and Alice was never redacted. `AgentPolicy.to_privacy_config()` was the
bridge and nothing called it. These tests drive each revived key through the PUBLIC API
from a real file on disk — asserting on the config object would pass while the wiring is
still absent.
"""
import textwrap

import pytest

from jataayu import jataayu_check_outbound
from jataayu.api import _get_outbound_guard, reset_guards


@pytest.fixture(autouse=True)
def _reset():
    reset_guards()
    yield
    reset_guards()


def write_policy(tmp_path, body: str, name: str = "jataayu-policy.yml") -> str:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return str(path)


class TestProtectedNamesFromPolicy:
    def test_policy_alone_redacts_a_protected_name(self, tmp_path):
        """The headline: no kwarg, just a policy file."""
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              privacy-bot:
                protected_names: [Alice]
        """)
        result = jataayu_check_outbound(
            "My daughter Alice loves coding",
            surface="discord-channel",
            policy_file=policy,
            agent="privacy-bot",
        )
        assert result["status"] in ("WARN", "BLOCK")
        assert "Alice" not in (result["redacted"] or "")

    def test_without_the_policy_the_same_name_passes(self, tmp_path):
        """Before/after control — the redaction above comes from the policy, not the PII scanner."""
        result = jataayu_check_outbound(
            "My daughter Alice loves coding", surface="discord-channel"
        )
        assert "Alice" in (result["redacted"] or "My daughter Alice loves coding")

    def test_kwarg_and_policy_names_are_merged(self, tmp_path):
        """A call-site name must not silently drop the org's roster."""
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              privacy-bot:
                protected_names: [Alice]
        """)
        guard = _get_outbound_guard(
            protected_names=["Bob"],
            policy=_agent_policy(policy, "privacy-bot"),
        )
        assert guard.config.protected_names == ["Alice", "Bob"]

    def test_defaults_block_resolves_with_no_agent_named(self, tmp_path):
        """policy_file= without agent= must go through `defaults:`, not yield nothing."""
        policy = write_policy(tmp_path, """
            version: 1
            defaults:
              internal_codenames: [Bluebird]
        """)
        result = jataayu_check_outbound(
            "The Bluebird launch slipped again.",
            surface="discord-channel",
            policy_file=policy,
        )
        assert result["status"] == "BLOCK"

    def test_unknown_agent_still_inherits_the_denying_defaults(self, tmp_path):
        """A typo'd agent name must not fail open."""
        policy = write_policy(tmp_path, """
            version: 1
            defaults:
              internal_codenames: [Bluebird]
            agents:
              privacy-bot:
                protected_names: [Alice]
        """)
        result = jataayu_check_outbound(
            "The Bluebird launch slipped again.",
            surface="discord-channel",
            policy_file=policy,
            agent="privacy-bt",
        )
        assert result["status"] == "BLOCK"

    def test_edited_policy_takes_effect_on_the_next_call(self, tmp_path):
        """No policy cache: three variants of one shipped here and all three failed open."""
        path = tmp_path / "jataayu-policy.yml"
        path.write_text("version: 1\nagents:\n  bot:\n    protected_names: [Alice]\n")
        first = jataayu_check_outbound(
            "Alice and Bob shipped it", surface="discord-channel",
            policy_file=str(path), agent="bot",
        )
        assert "Alice" not in (first["redacted"] or "")

        path.write_text("version: 1\nagents:\n  bot:\n    protected_names: [Bob]\n")
        second = jataayu_check_outbound(
            "Alice and Bob shipped it", surface="discord-channel",
            policy_file=str(path), agent="bot",
        )
        assert "Bob" not in (second["redacted"] or "")
        assert "Alice" in (second["redacted"] or "")


class TestPolicyIsPartOfTheGuardCacheKey:
    """The identical defect, one layer up: policy now feeds the config that builds the
    guard, so a cached guard from policy A must not be served to a call naming policy B.
    These deliberately do NOT reset between calls — the reset is what hides it."""

    def test_second_policy_file_is_not_served_the_first_ones_guard(self, tmp_path):
        a = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                protected_names: [Alice]
        """, name="a.yml")
        b = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                protected_names: [Bob]
        """, name="b.yml")

        first = jataayu_check_outbound(
            "Alice and Bob shipped it", surface="discord-channel",
            policy_file=a, agent="bot",
        )
        assert "Alice" not in (first["redacted"] or "")

        second = jataayu_check_outbound(
            "Alice and Bob shipped it", surface="discord-channel",
            policy_file=b, agent="bot",
        )
        assert "Bob" not in (second["redacted"] or ""), "policy A's guard was reused for B"

    def test_dropping_the_policy_drops_its_names(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                protected_names: [Alice]
        """)
        jataayu_check_outbound(
            "Alice shipped it", surface="discord-channel", policy_file=policy, agent="bot",
        )
        guard = _get_outbound_guard()
        assert guard.config.protected_names == []

    def test_a_non_privacy_edit_still_rebuilds_the_guard(self, tmp_path):
        """check_high_entropy is not in protected_names, so a key derived from names
        alone would miss it."""
        off = write_policy(tmp_path, """
            version: 1
            defaults:
              check_high_entropy: false
        """, name="off.yml")
        on = write_policy(tmp_path, """
            version: 1
            defaults:
              check_high_entropy: true
        """, name="on.yml")

        a = _get_outbound_guard(policy=_agent_policy(off, ""))
        b = _get_outbound_guard(policy=_agent_policy(on, ""))
        assert a is not b
        assert b.config.check_high_entropy is True


class TestEveryRevivedKeyChangesBehaviour:
    def test_internal_codenames_block_on_every_surface(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                internal_codenames: [Bluebird]
        """)
        text = "The Bluebird rollout is delayed."
        assert jataayu_check_outbound(text, surface="internal")["status"] == "SAFE"
        assert jataayu_check_outbound(
            text, surface="internal", policy_file=policy, agent="bot"
        )["status"] == "BLOCK"

    def test_gtm_codenames_are_held_on_a_social_surface(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                gtm_codenames: [Skylark]
        """)
        result = jataayu_check_outbound(
            "Skylark ships next week.", surface="group-chat",
            policy_file=policy, agent="bot",
        )
        assert result["status"] in ("WARN", "BLOCK")

    def test_check_credentials_false_stops_the_credential_scan(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                check_credentials: false
        """)
        secret = "here is the key sk-abcdefghij0123456789abcdefghij0123456789abcd"
        assert jataayu_check_outbound(secret, surface="discord-channel")["status"] != "SAFE"
        assert jataayu_check_outbound(
            secret, surface="discord-channel", policy_file=policy, agent="bot",
        )["status"] == "SAFE"

    def test_disabled_cred_rules_silences_one_rule(self, tmp_path):
        secret = "here is the key sk-abcdefghij0123456789abcdefghij0123456789abcd"
        baseline = jataayu_check_outbound(secret, surface="discord-channel")
        rule = _first_cred_rule(baseline)
        policy = write_policy(tmp_path, f"""
            version: 1
            agents:
              bot:
                disabled_cred_rules: [{rule}]
        """)
        after = jataayu_check_outbound(
            secret, surface="discord-channel", policy_file=policy, agent="bot",
        )
        assert rule not in after["findings"]

    def test_check_high_entropy_adds_a_finding(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                check_high_entropy: true
        """)
        blob = "config value: aG9sZHRoaXNzZWNyZXR2YWx1ZWhlcmVub3dwbGVhc2V4eXo"
        assert jataayu_check_outbound(blob, surface="discord-channel")["status"] == "SAFE"
        assert jataayu_check_outbound(
            blob, surface="discord-channel", policy_file=policy, agent="bot",
        )["status"] != "SAFE"

    def test_defaults_are_inherited_by_a_named_agent(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            defaults:
              internal_codenames: [Bluebird]
            agents:
              bot:
                protected_names: [Alice]
        """)
        result = jataayu_check_outbound(
            "Bluebird is on track.", surface="internal", policy_file=policy, agent="bot",
        )
        assert result["status"] == "BLOCK"


class TestOutOfScopeKeysAreNotWired:
    """use_llm / llm_threshold / block_threshold from policy are a separate decision.
    A policy saying `use_llm: true` must not silently turn on a network call here."""

    def test_policy_use_llm_does_not_switch_on_the_llm_path(self, tmp_path):
        policy = write_policy(tmp_path, """
            version: 1
            agents:
              bot:
                use_llm: true
                llm_threshold: 0.01
                block_threshold: 0.01
        """)
        guard = _get_outbound_guard(policy=_agent_policy(policy, "bot"))
        assert guard.config.use_llm is False
        assert guard.config.block_threshold == 0.9


def _agent_policy(path: str, agent: str):
    from jataayu.config.policy import load_policy

    return load_policy(path).get_agent_policy(agent)


def _first_cred_rule(result: dict) -> str:
    import re

    match = re.search(r"CRED_\d+", result["findings"])
    assert match, f"no credential rule in findings: {result['findings']!r}"
    return match.group(0)
