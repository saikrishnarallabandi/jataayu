"""
Tests for the SCR-Bench composition dimensions added to check_skillset:
trust-transfer (endorsement laundering a dangerous capability) and intent
fragmentation (a dangerous chain spread across 3+ skills). No LLM required.
"""
from jataayu.guards.composition import check_skillset


def _skill(name, caps, **kw):
    return {"name": name, "capabilities": caps, **kw}


class TestTrustTransfer:
    def test_endorsed_dangerous_contributor_is_malicious(self):
        # Exfil combo (reads_secrets + network_write) split across two skills,
        # and the network_write skill is ENDORSED — endorsement must not launder it.
        risk = check_skillset([
            _skill("vault-reader", ["reads_secrets"]),
            _skill("telemetry", ["network_write"], endorsed=True),
        ])
        assert risk.verdict == "MALICIOUS"
        assert risk.trust_transfer
        assert risk.trust_transfer[0]["skill"] == "telemetry"

    def test_unendorsed_same_combo_is_review_only(self):
        # Identical combo, nobody endorsed -> stays REVIEW (unchanged legacy behavior).
        risk = check_skillset([
            _skill("vault-reader", ["reads_secrets"]),
            _skill("telemetry", ["network_write"]),
        ])
        assert risk.verdict == "REVIEW"
        assert risk.trust_transfer == []

    def test_endorsed_but_no_dangerous_combo_is_safe(self):
        # Endorsement on a benign skill with no realized dangerous combo is fine.
        risk = check_skillset([
            _skill("themer", ["fs_read"], endorsed=True),
            _skill("formatter", ["fs_read"]),
        ])
        assert risk.verdict == "SAFE"
        assert risk.trust_transfer == []


class TestFragmentation:
    def test_combo_across_three_skills_marked_fragmented(self):
        # download-and-run (exec + network_read) with a third skill also contributing
        # network_read -> 3 distinct contributors -> fragmented.
        # exec (runner) + network_read (fetcher, updater): 3 distinct contributors,
        # no single skill holds both -> a real cross-skill combo, fragmented.
        risk = check_skillset([
            _skill("runner", ["exec"]),
            _skill("fetcher", ["network_read"]),
            _skill("updater", ["network_read"]),
        ])
        assert any(c.get("fragmented") for c in risky_if(risk)), risk.explanation

    def test_two_skill_combo_not_fragmented(self):
        risk = check_skillset([
            _skill("runner", ["exec"]),
            _skill("fetcher", ["network_read"]),
        ])
        assert all(not c.get("fragmented") for c in risky_if(risk))


def risky_if(risk):
    return risk.risky_combinations


class TestSerialization:
    def test_to_dict_has_trust_transfer(self):
        risk = check_skillset([
            _skill("vault-reader", ["reads_secrets"]),
            _skill("telemetry", ["network_write"], endorsed=True),
        ])
        d = risk.to_dict()
        assert "trust_transfer" in d
        assert d["trust_transfer"]
