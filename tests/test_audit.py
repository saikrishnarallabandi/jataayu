"""
Tests for Jataayu SessionTrace — cross-turn runtime behavioral auditing.

Covers the trajectory patterns that single-shot guards cannot see:
exfil chains realized across turns, sleeper memory poisoning, untrusted input
into a critical effect, and escalating trajectories — plus false-positive
controls on benign trajectories. No LLM required.
"""
import pytest

from jataayu.core.audit import SessionTrace, AuditRisk
from jataayu.guards.effect_boundary import Provenance, EffectClass


# ---------------------------------------------------------------------------
# Cross-turn exfiltration chain
# ---------------------------------------------------------------------------

class TestCrossTurnExfil:
    def test_secret_read_then_network_flagged(self):
        t = SessionTrace()
        t.record("web_fetch", untrusted=True, turn=1)     # untrusted content enters
        t.record("read_secret", untrusted=True, turn=2)   # secret read
        t.record("http_request", untrusted=True, turn=5)  # egress later
        r = t.audit()
        assert r.risk == AuditRisk.HIGH
        patterns = {f.pattern for f in r.findings}
        assert "cross_turn_exfil_chain" in patterns

    def test_trusted_secret_read_no_egress_finding(self):
        # Trusted secret read + trusted local file write, no untrusted influence.
        t = SessionTrace()
        t.record("read_secret", untrusted=False, turn=1)
        t.record("write_file", untrusted=False, turn=2)
        r = t.audit()
        assert "cross_turn_exfil_chain" not in {f.pattern for f in r.findings}

    def test_egress_before_secret_is_not_a_chain(self):
        # Order matters: egress must come AFTER the secret read.
        t = SessionTrace()
        t.record("http_request", untrusted=True, turn=1)
        t.record("read_secret", untrusted=True, turn=2)
        r = t.audit()
        assert "cross_turn_exfil_chain" not in {f.pattern for f in r.findings}


# ---------------------------------------------------------------------------
# Sleeper memory poisoning
# ---------------------------------------------------------------------------

class TestSleeperMemory:
    def test_flagged_write_then_read_then_shell(self):
        t = SessionTrace()
        t.record("save_memory", untrusted=True, inbound_flagged=True, turn=1)
        t.record("recall", untrusted=True, turn=4)
        t.record("bash", untrusted=True, turn=4)
        r = t.audit()
        assert "sleeper_memory_poisoning" in {f.pattern for f in r.findings}
        assert r.risk == AuditRisk.HIGH

    def test_untrusted_write_without_flag_is_medium(self):
        t = SessionTrace()
        t.record("save_memory", untrusted=True, inbound_flagged=False, turn=1)
        t.record("recall", untrusted=True, turn=3)
        t.record("http_request", untrusted=True, turn=3)
        r = t.audit()
        finding = next(f for f in r.findings if f.pattern == "sleeper_memory_poisoning")
        assert finding.risk == AuditRisk.MEDIUM

    def test_no_later_read_no_sleeper(self):
        t = SessionTrace()
        t.record("save_memory", untrusted=True, inbound_flagged=True, turn=1)
        t.record("bash", untrusted=False, turn=2)  # dangerous but no recall between
        r = t.audit()
        assert "sleeper_memory_poisoning" not in {f.pattern for f in r.findings}


# ---------------------------------------------------------------------------
# Untrusted into critical effect (single-event)
# ---------------------------------------------------------------------------

class TestUntrustedCritical:
    def test_untrusted_shell_flagged(self):
        t = SessionTrace()
        t.record("bash", untrusted=True)
        r = t.audit()
        assert "untrusted_into_critical_effect" in {f.pattern for f in r.findings}
        assert r.risk == AuditRisk.HIGH

    def test_trusted_shell_ok(self):
        t = SessionTrace()
        t.record("bash", untrusted=False)
        r = t.audit()
        assert r.is_clean


# ---------------------------------------------------------------------------
# Escalating trajectory
# ---------------------------------------------------------------------------

class TestEscalation:
    def test_monotonic_severity_climb(self):
        t = SessionTrace()
        t.record("read_file", untrusted=True, effect_class=EffectClass.READ, turn=1)
        t.record("write_file", untrusted=True, effect_class=EffectClass.FILE_WRITE, turn=2)
        t.record("http.post", untrusted=True, effect_class=EffectClass.NETWORK, turn=3)
        r = t.audit()
        assert "escalating_trajectory" in {f.pattern for f in r.findings}


# ---------------------------------------------------------------------------
# Benign trajectories — no false positives
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_clean_trusted_session(self):
        t = SessionTrace()
        t.record("read_file", untrusted=False, turn=1)
        t.record("write_file", untrusted=False, turn=2)
        r = t.audit()
        assert r.is_clean
        assert r.findings == []

    def test_untrusted_reads_only(self):
        t = SessionTrace()
        t.record("read_file", untrusted=True, turn=1)
        t.record("read_file", untrusted=True, turn=2)
        r = t.audit()
        assert r.is_clean


# ---------------------------------------------------------------------------
# Profiling & serialization
# ---------------------------------------------------------------------------

class TestProfileAndSerialize:
    def test_profile_counts(self):
        t = SessionTrace()
        t.record("read_file", untrusted=False)
        t.record("read_file", untrusted=False)
        t.record("bash", untrusted=False)
        prof = t.profile()
        assert prof.get("read") == 2
        assert prof.get("shell") == 1

    def test_auto_turn_increment(self):
        t = SessionTrace()
        e1 = t.record("read_file")
        e2 = t.record("read_file")
        assert e1.turn == 1 and e2.turn == 2

    def test_to_dict_shape(self):
        t = SessionTrace(session_id="s1")
        t.record("bash", untrusted=True)
        d = t.to_dict()
        assert d["session_id"] == "s1"
        assert d["audit"]["risk"] == "high"
        assert len(d["events"]) == 1

    def test_trace_classifies_with_the_given_boundary(self):
        """Without the boundary, the audit disagrees with the guard that decided the call."""
        from jataayu.guards.effect_boundary import EffectBoundary

        boundary = EffectBoundary(tool_effects={"internal.run_playbook": "shell"})
        t = SessionTrace(boundary=boundary)
        e = t.record("internal.run_playbook", untrusted=True)
        assert e.effect_class is EffectClass.SHELL
        assert t.audit().risk == AuditRisk.HIGH

        assert SessionTrace().record(
            "internal.run_playbook", untrusted=True,
        ).effect_class is EffectClass.READ
