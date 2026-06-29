"""
Tests for compositional skillset analysis ("When Safe Skills Collide") and the
per-agent capability-isolation policy.

Most tests pass skills as dicts with explicit capabilities so they're deterministic
and offline; a couple exercise path-vetting and the convenience API.
"""
import pytest

from jataayu import jataayu_check_skillset, check_skillset, CompositionRisk
from jataayu.guards.skill_vet import SkillVetResult
from jataayu.config.policy import AgentPolicy, PolicyLoader


def skill(name, caps, verdict=None):
    d = {"name": name, "capabilities": caps}
    if verdict:
        d["verdict"] = verdict
    return d


# ---------------------------------------------------------------------------
# Cross-skill dangerous combinations
# ---------------------------------------------------------------------------

def test_two_safe_skills_compose_to_exfil():
    skills = [
        skill("vault-reader", ["reads_secrets", "fs_read"]),
        skill("uploader", ["network_write"]),
    ]
    risk = check_skillset(skills)
    assert risk.verdict == "REVIEW"
    combos = risk.risky_combinations
    assert any("exfiltration" in c["description"] for c in combos)
    # The combo reports which skill contributes each capability.
    exfil = next(c for c in combos if "exfiltration" in c["description"])
    assert exfil["contributors"]["reads_secrets"] == ["vault-reader"]
    assert exfil["contributors"]["network_write"] == ["uploader"]


def test_single_skill_holding_both_is_not_a_cross_skill_combo():
    # One skill with both caps is intra-skill (P0's job), not a composition risk.
    skills = [skill("all-in-one", ["reads_secrets", "network_write"])]
    risk = check_skillset(skills)
    assert risk.risky_combinations == []
    assert risk.verdict == "SAFE"


def test_dropper_combo_across_skills():
    skills = [
        skill("writer", ["fs_write"]),
        skill("runner", ["exec"]),
    ]
    risk = check_skillset(skills)
    assert any("dropper" in c["description"] for c in risk.risky_combinations)


def test_memory_poisoning_vector_with_any_other_skill():
    skills = [
        skill("notetaker", ["memory_write"]),
        skill("helper", ["fs_read"]),
    ]
    risk = check_skillset(skills)
    assert any("memory-poisoning" in c["description"] for c in risk.risky_combinations)
    assert risk.verdict == "REVIEW"


def test_lone_memory_writer_is_safe():
    risk = check_skillset([skill("notetaker", ["memory_write"])])
    assert risk.verdict == "SAFE"
    assert risk.risky_combinations == []


def test_benign_skillset_is_safe():
    skills = [
        skill("weather", ["network_read"]),
        skill("formatter", ["fs_read"]),
    ]
    risk = check_skillset(skills)
    assert risk.verdict == "SAFE"
    assert risk.is_safe


# ---------------------------------------------------------------------------
# Individually-flagged skills propagate to the set verdict
# ---------------------------------------------------------------------------

def test_individually_malicious_skill_makes_set_malicious():
    skills = [
        skill("evil", ["exec"], verdict="MALICIOUS"),
        skill("benign", ["fs_read"]),
    ]
    risk = check_skillset(skills)
    assert risk.verdict == "MALICIOUS"
    assert {"skill": "evil", "verdict": "MALICIOUS"} in risk.individually_flagged


def test_accepts_skillvetresult_input():
    svr = SkillVetResult(verdict="SAFE", capabilities=["network_write"], skill_name="api")
    skills = [svr, skill("reader", ["reads_secrets"])]
    risk = check_skillset(skills)
    assert "api" in risk.skills
    assert any("exfiltration" in c["description"] for c in risk.risky_combinations)


def test_duplicate_names_disambiguated():
    skills = [skill("dup", ["fs_read"]), skill("dup", ["network_read"])]
    risk = check_skillset(skills)
    assert len(risk.skills) == 2
    assert "dup" in risk.skills and "dup#2" in risk.skills


# ---------------------------------------------------------------------------
# Capability isolation via policy
# ---------------------------------------------------------------------------

def test_agent_policy_capability_allowlist():
    p = AgentPolicy(name="restricted", allowed_capabilities=["network_read", "fs_read"])
    assert p.is_capability_allowed("network_read") is True
    assert p.is_capability_allowed("exec") is False
    assert p.capability_violations(["network_read", "exec", "fs_write"]) == ["exec", "fs_write"]


def test_agent_policy_forbidden_capabilities():
    p = AgentPolicy(name="a", forbidden_capabilities=["exec"])
    # Allowlist empty → everything allowed except the forbidden one.
    assert p.is_capability_allowed("network_write") is True
    assert p.is_capability_allowed("exec") is False


def test_check_skillset_blocks_forbidden_capability_at_install():
    policy = AgentPolicy(name="bot", allowed_capabilities=["network_read"])
    skills = [skill("a", ["network_read"]), skill("b", ["exec"])]
    risk = check_skillset(skills, policy=policy)
    assert risk.verdict == "MALICIOUS"
    assert any(v["capability"] == "exec" for v in risk.policy_violations)
    viol = next(v for v in risk.policy_violations if v["capability"] == "exec")
    assert viol["contributors"] == ["b"]


def test_check_skillset_with_policy_object_and_agent():
    policy = PolicyLoader.from_dict({
        "version": 1,
        "agents": {
            "github-bot": {"allowed_capabilities": ["network_read", "fs_read"]},
        },
    })
    skills = [skill("fetcher", ["network_read"]), skill("shell", ["exec"])]
    risk = check_skillset(skills, policy=policy, agent="github-bot")
    assert risk.verdict == "MALICIOUS"
    assert any(v["capability"] == "exec" for v in risk.policy_violations)


def test_policy_loader_parses_capability_lists():
    policy = PolicyLoader.from_dict({
        "version": 1,
        "agents": {
            "bot": {
                "allowed_capabilities": ["network_read"],
                "forbidden_capabilities": ["exec", "reads_secrets"],
            },
        },
    })
    ap = policy.get_agent_policy("bot")
    assert ap.allowed_capabilities == ["network_read"]
    assert ap.forbidden_capabilities == ["exec", "reads_secrets"]
    assert "allowed_capabilities" in ap.to_dict()


# ---------------------------------------------------------------------------
# Path vetting + convenience API + result shape
# ---------------------------------------------------------------------------

def test_check_skillset_vets_paths(tmp_path):
    a = tmp_path / "reader"
    a.mkdir()
    (a / "main.py").write_text("import os\nkey = os.environ['TOKEN']\n")
    b = tmp_path / "sender"
    b.mkdir()
    (b / "main.py").write_text("import requests\nrequests.post('https://x.example/u', data={})\n")

    risk = check_skillset([str(a), str(b)], use_llm=False)
    assert "reads_secrets" in risk.aggregate_capabilities
    assert "network_write" in risk.aggregate_capabilities
    assert any("exfiltration" in c["description"] for c in risk.risky_combinations)


def test_convenience_api_check_skillset():
    res = jataayu_check_skillset([
        skill("a", ["reads_secrets"]),
        skill("b", ["network_write"]),
    ])
    assert res["verdict"] == "REVIEW"
    for key in ("verdict", "skills", "aggregate_capabilities", "risky_combinations",
                "policy_violations", "individually_flagged", "explanation"):
        assert key in res


def test_result_repr_and_to_dict():
    risk = check_skillset([skill("a", ["fs_read"])])
    assert isinstance(risk, CompositionRisk)
    assert "CompositionRisk" in repr(risk)
    assert risk.to_dict()["verdict"] == "SAFE"


def test_invalid_input_type_raises():
    with pytest.raises(TypeError):
        check_skillset([12345])
