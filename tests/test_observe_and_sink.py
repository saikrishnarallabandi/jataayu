"""
Tests for observe mode, the decision sink, and the configurable tool→effect map.

The contract under test is backwards compatibility: `decision` keeps meaning "what was
ENFORCED" and stays 3-valued, so every existing caller that string-compares it keeps
working. The truthful verdict lives in the new `would_decision` key.
"""
import pytest

from jataayu import jataayu_authorize_action, set_decision_sink, SecurityError
from jataayu.core import audit
from jataayu.guards.effect_boundary import (
    EffectBoundary, Value, Provenance, EffectClass, Decision, CommitRejected,
)
from tests import test_effect_boundary as _eb

# Via the module, not `from ... import TestClassification` — a bare Test* name at module
# level would make pytest re-collect that whole class here, without its fixtures.
SECRET_MUST_DENY = _eb.TestClassification.SECRET_MUST_DENY

U = lambda d: Value(d, Provenance.UNTRUSTED, source="web-page")
T = lambda d: Value(d, Provenance.TRUSTED, source="operator")

LEGACY_KEYS = {
    "tool_name", "effect_class", "provenance", "decision",
    "reason", "violations", "commit_token",
}


@pytest.fixture(autouse=True)
def _clear_sink():
    """No test may leak a module-level sink into another."""
    set_decision_sink(None)
    yield
    set_decision_sink(None)


class TestObserveMode:
    def test_readme_pattern_does_not_raise_in_observe_mode(self):
        """The exact pattern the README tells users to write must not fire in observe mode."""
        decision = jataayu_authorize_action(
            "shell.exec", {"command": "rm -rf /"}, mode="observe",
        )

        # Verbatim from the README:
        if decision["decision"] == "deny":
            raise SecurityError(decision["reason"])

        # ...and yet the truthful verdict is still legible.
        assert decision["would_decision"] == "deny"
        assert decision["tripwire_triggered"] is True
        assert decision["mode"] == "observe"

    def test_enforce_mode_still_denies(self):
        d = jataayu_authorize_action("shell.exec", {"command": "rm -rf /"})
        assert d["decision"] == "deny"
        assert d["commit_token"] is None

    def test_enforce_mode_to_dict_is_exactly_the_legacy_keys(self):
        """Regression lock: enforce-mode output must stay byte-for-byte compatible."""
        for tool in ("shell.exec", "read_file", "http.post"):
            d = jataayu_authorize_action(tool, {"x": 1})
            assert set(d) == LEGACY_KEYS, f"{tool} leaked new keys into enforce mode"

    def test_observe_adds_exactly_three_keys(self):
        d = jataayu_authorize_action("shell.exec", {"x": 1}, mode="observe")
        assert set(d) - LEGACY_KEYS == {"mode", "would_decision", "tripwire_triggered"}

    def test_observe_on_an_action_that_would_pass_anyway(self):
        d = jataayu_authorize_action("read_file", {"path": "/tmp/x"}, mode="observe")
        assert d["decision"] == "allow"
        assert d["would_decision"] == "allow"
        assert d["tripwire_triggered"] is False

    def test_observe_issues_a_token_and_commit_succeeds_on_a_would_deny(self):
        b = EffectBoundary(mode="observe")
        params = {"command": "rm -rf /"}
        pv = b.preview("shell.exec", params, [U("payload")])

        assert pv.decision is Decision.ALLOW
        assert pv.would_decision is Decision.DENY
        assert pv.commit_token is not None
        assert b.commit(pv, params, lambda: "ran") == "ran"

    def test_enforce_mode_commit_still_rejected(self):
        b = EffectBoundary()
        pv = b.preview("shell.exec", {"command": "x"}, [U("payload")])
        with pytest.raises(CommitRejected):
            b.commit(pv, {"command": "x"}, lambda: "ran")

    def test_observe_reason_is_prefixed(self):
        d = jataayu_authorize_action("shell.exec", {"x": 1}, mode="observe")
        assert d["reason"].startswith("observe mode: would deny — ")

    def test_observe_does_not_defeat_the_commit_token_binding(self):
        """Observe relaxes the verdict, never the anti-mutation binding."""
        b = EffectBoundary(mode="observe")
        pv = b.preview("shell.exec", {"command": "ls"}, [U("payload")])
        with pytest.raises(CommitRejected):
            b.commit(pv, {"command": "rm -rf /"}, lambda: "ran")

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="obseve"):
            EffectBoundary(mode="obseve")

    def test_mode_defaults_to_enforce(self):
        assert EffectBoundary().mode == "enforce"


class TestDecisionSink:
    def test_record_shape_on_deny(self):
        records = []
        set_decision_sink(records.append)
        jataayu_authorize_action("shell.exec", {"command": "rm -rf /"})

        assert len(records) == 1
        r = records[0]
        assert r["rail_type"] == "effect_boundary"
        assert r["tool_name"] == "shell.exec"
        assert r["effect_class"] == "shell"
        assert r["provenance"] == "untrusted"
        assert r["decision"] == "deny"
        assert r["would_decision"] == "deny"
        assert r["tripwire_triggered"] is True
        assert r["mode"] == "enforce"
        assert r["unrecognized"] is False

    def test_record_shape_on_allow(self):
        records = []
        set_decision_sink(records.append)
        jataayu_authorize_action("read_file", {"path": "/tmp/x"})
        r = records[0]
        assert r["decision"] == "allow"
        assert r["would_decision"] == "allow"
        assert r["tripwire_triggered"] is False

    def test_record_separates_enforced_from_truthful_in_observe(self):
        records = []
        set_decision_sink(records.append)
        jataayu_authorize_action("shell.exec", {"x": 1}, mode="observe")
        r = records[0]
        assert (r["decision"], r["would_decision"]) == ("allow", "deny")

    def test_unrecognized_flag_tracks_the_fallback(self):
        records = []
        set_decision_sink(records.append)
        jataayu_authorize_action("frobnicate.widget", {"x": 1})
        assert records[0]["unrecognized"] is True

    def test_a_raising_sink_neither_propagates_nor_changes_the_verdict(self):
        def broken(record):
            raise ZeroDivisionError("your telemetry is on fire")

        set_decision_sink(broken)
        d = jataayu_authorize_action("shell.exec", {"command": "rm -rf /"})
        assert d["decision"] == "deny"
        assert d["reason"]

    def test_a_raising_sink_is_logged(self, caplog):
        set_decision_sink(lambda r: 1 / 0)
        with caplog.at_level("ERROR", logger="jataayu"):
            jataayu_authorize_action("read_file", {"x": 1})
        assert "decision sink raised" in caplog.text

    def test_capture_content_off_by_default(self):
        records = []
        set_decision_sink(records.append)
        jataayu_authorize_action("read_file", {"password": "hunter2"})
        assert "params" not in records[0]

    def test_capture_content_on_includes_params(self):
        records = []
        set_decision_sink(records.append, capture_content=True)
        jataayu_authorize_action("read_file", {"path": "/tmp/x"})
        assert records[0]["params"] == {"path": "/tmp/x"}

    def test_per_instance_sink_beats_module_level(self):
        module_records, instance_records = [], []
        set_decision_sink(module_records.append)

        EffectBoundary(sink=instance_records.append).preview("read_file", {}, [U("x")])

        assert len(instance_records) == 1
        assert module_records == []

    def test_per_instance_capture_content_beats_module_level(self):
        records = []
        set_decision_sink(records.append, capture_content=False)
        EffectBoundary(sink=records.append, capture_content=True).preview(
            "read_file", {"path": "/tmp/x"}, [U("x")],
        )
        assert records[0]["params"] == {"path": "/tmp/x"}

    def test_no_sink_installed_is_a_noop(self):
        assert jataayu_authorize_action("read_file", {"x": 1})["decision"] == "allow"

    def test_sink_can_be_uninstalled(self):
        records = []
        set_decision_sink(records.append)
        jataayu_authorize_action("read_file", {"x": 1})
        set_decision_sink(None)
        jataayu_authorize_action("read_file", {"x": 1})
        assert len(records) == 1

    def test_emit_decision_never_raises_without_a_sink(self):
        audit.emit_decision({"anything": True})

    def test_a_sink_raising_a_base_exception_does_not_propagate(self):
        """'Never raises' has to mean BaseException too — SystemExit, gevent.Timeout,
        a library's cancellation type — or a telemetry callback eats the deny."""
        class Boom(BaseException):
            pass

        set_decision_sink(lambda r: (_ for _ in ()).throw(Boom("cancelled")))
        d = jataayu_authorize_action("shell.exec", {"command": "rm -rf /"})
        assert d["decision"] == "deny"

    def test_a_sink_raising_system_exit_does_not_propagate(self):
        def bail(record):
            raise SystemExit(1)

        set_decision_sink(bail)
        assert jataayu_authorize_action("shell.exec", {"x": 1})["decision"] == "deny"

    def test_keyboard_interrupt_from_a_sink_still_propagates(self):
        """Deliberate carve-out: Ctrl-C is the operator, not a broken sink."""
        def interrupted(record):
            raise KeyboardInterrupt

        set_decision_sink(interrupted)
        with pytest.raises(KeyboardInterrupt):
            jataayu_authorize_action("read_file", {"x": 1})


class TestSinkCannotMutateTheDecision:
    """The sink is telemetry. It must not be able to touch caller-visible state."""

    def test_sink_cannot_clear_the_violations_of_a_deny(self):
        from jataayu.config.policy import AgentPolicy

        set_decision_sink(lambda r: r["violations"].clear())
        policy = AgentPolicy(name="a", forbidden_capabilities=["exec"])
        pv = EffectBoundary(policy=policy).preview("shell.exec", {"command": "ls"}, [U("p")])

        assert pv.decision is Decision.DENY
        assert pv.to_dict()["violations"] == ["exec"]

    def test_sink_cannot_rewrite_the_callers_params(self):
        """capture_content puts params in the record; a sink that redacts in place must
        not rewrite the dict that was classified and bound into the commit token."""
        def redact(record):
            record["params"]["cmd"] = "rm -rf /"

        set_decision_sink(redact, capture_content=True)
        params = {"cmd": "ls"}
        EffectBoundary().preview("shell.exec", params, [U("p")])

        assert params == {"cmd": "ls"}

    def test_sink_cannot_reach_nested_caller_state(self):
        def stomp(record):
            record["params"]["env"]["PATH"] = "/tmp/evil"

        set_decision_sink(stomp, capture_content=True)
        params = {"env": {"PATH": "/usr/bin"}}
        EffectBoundary().preview("read_file", params, [U("p")])

        assert params == {"env": {"PATH": "/usr/bin"}}

    def test_an_uncopyable_param_still_reaches_the_sink(self):
        """Degrade to repr rather than dropping the record — telemetry must still fire."""
        import threading

        records = []
        set_decision_sink(records.append, capture_content=True)
        EffectBoundary().preview("read_file", {"lock": threading.Lock()}, [U("p")])

        assert records and "lock" in records[0]["params"]

    def test_the_sink_still_sees_the_real_values(self):
        records = []
        set_decision_sink(records.append, capture_content=True)
        EffectBoundary().preview("shell.exec", {"cmd": "ls"}, [U("p")])

        assert records[0]["params"] == {"cmd": "ls"}
        assert records[0]["decision"] == "deny"


class TestToolEffectsMapping:
    def test_mapping_flips_an_unrecognized_name(self):
        b = EffectBoundary(tool_effects={"jira.create_issue": "network"})
        pv = b.preview("jira.create_issue", {"title": "x"}, [U("payload")])
        assert pv.effect_class is EffectClass.NETWORK
        assert pv.decision is Decision.NEEDS_APPROVAL

    def test_unmapped_the_same_name_is_allowed(self):
        """Control for the test above — without the map it falls through to READ."""
        pv = EffectBoundary().preview("jira.create_issue", {"title": "x"}, [U("payload")])
        assert pv.decision is Decision.ALLOW

    def test_mapping_overrides_a_builtin_not_just_gaps(self):
        """The user pain is a false positive on their OWN tool name; fill-gaps can't fix it."""
        b = EffectBoundary(tool_effects={"bash": "read"})
        pv = b.preview("bash", {"command": "ls"}, [U("payload")])
        assert pv.effect_class is EffectClass.READ
        assert pv.decision is Decision.ALLOW

    def test_mapping_accepts_effectclass_members(self):
        b = EffectBoundary(tool_effects={"widget.frob": EffectClass.SHELL})
        assert b.classify("widget.frob") is EffectClass.SHELL

    def test_mapping_is_case_and_whitespace_insensitive(self):
        b = EffectBoundary(tool_effects={"  Jira.Create_Issue  ": "shell"})
        assert b.classify("jira.create_issue") is EffectClass.SHELL

    def test_invalid_effect_value_raises(self):
        with pytest.raises(ValueError, match="shel"):
            EffectBoundary(tool_effects={"x": "shel"})

    def test_mapped_names_are_recognized(self):
        records = []
        b = EffectBoundary(tool_effects={"frobnicate.widget": "read"}, sink=records.append)
        b.preview("frobnicate.widget", {}, [U("x")])
        assert records[0]["unrecognized"] is False


class TestStrictUnknownTools:
    def test_strict_gates_an_unrecognized_untrusted_call(self):
        b = EffectBoundary(strict=True)
        pv = b.preview("frobnicate.widget", {"x": 1}, [U("payload")])
        assert pv.decision is Decision.NEEDS_APPROVAL
        assert pv.reason == "unrecognized tool name; strict mode requires approval"
        assert pv.unrecognized is True

    def test_strict_allows_an_unrecognized_TRUSTED_call(self):
        """A trusted call has no attacker in the loop; the boundary already allows trusted→shell."""
        b = EffectBoundary(strict=True)
        pv = b.preview("frobnicate.widget", {"x": 1}, [T("operator input")])
        assert pv.decision is Decision.ALLOW

    def test_strict_defaults_off(self):
        assert EffectBoundary().strict is False
        pv = EffectBoundary().preview("frobnicate.widget", {"x": 1}, [U("payload")])
        assert pv.decision is Decision.ALLOW

    def test_strict_gates_an_empty_tool_name(self):
        pv = EffectBoundary(strict=True).preview("", {}, [U("payload")])
        assert pv.decision is Decision.NEEDS_APPROVAL

    @pytest.mark.parametrize("tool", SECRET_MUST_DENY)
    def test_strict_does_not_change_a_recognized_verdict(self, tool):
        """Strict only touches the unrecognized fallback — recognized names decide as before."""
        strict = EffectBoundary(strict=True).preview(tool, {"p": 1}, [U("payload")])
        plain = EffectBoundary().preview(tool, {"p": 1}, [U("payload")])
        assert strict.decision is plain.decision is Decision.DENY

    def test_capability_denial_still_wins_over_strict(self):
        """A forbidden capability is a deny, not a 'please approve'."""
        from jataayu.config.policy import AgentPolicy

        policy = AgentPolicy(name="a", forbidden_capabilities=["fs_read"])
        pv = EffectBoundary(policy=policy, strict=True).preview(
            "frobnicate.widget", {"x": 1}, [U("payload")],
        )
        assert pv.decision is Decision.DENY
        assert "fs_read" in pv.violations

    def test_strict_via_api_kwarg(self):
        d = jataayu_authorize_action("frobnicate.widget", {"x": 1}, strict=True)
        assert d["decision"] == "needs_approval"
