"""
Jataayu compositional skill analysis
====================================
Individually-safe skills compose into unsafe capability sets.

The 2026 literature ("When Safe Skills Collide", arXiv:2606.00448) shows that
per-skill scanning misses risk that only emerges from *combinations*: skill A reads
secrets, skill B writes to the network — each benign alone, an exfiltration channel
together. One registry held ~14K such genuine risk memberships *by construction*.

This module reasons about a *set* of installed skills:
  1. Tag each skill's capabilities (reuses the P0 SkillVetGuard pass).
  2. Flag dangerous capability pairs/chains realized across the set (cross-skill),
     reporting which skills contribute each capability.
  3. Enforce per-agent capability allowlists (config/policy.py) — a composition that
     unlocks a forbidden capability is blocked at INSTALL, not discovered at runtime.

Usage:
    from jataayu.guards.composition import check_skillset
    risk = check_skillset(["skills/a", "skills/b"], policy=policy, agent="github-bot")
    if risk.verdict == "MALICIOUS":
        raise PermissionError(risk.explanation)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from jataayu.guards.skill_vet import DANGEROUS_COMBOS, SkillVetGuard, SkillVetResult


# memory_write + any other instruction-following skill = poisoning vector: one skill
# can persist attacker content that any other skill later acts on. Modelled separately
# from the capability-pair combos because the second half is "any skill", not a capability.
_MEMORY_POISON_CAP = "memory_write"


@dataclass
class CompositionRisk:
    """
    Result of analysing a set of skills for compositional risk.

    Attributes:
        verdict: SAFE | REVIEW | MALICIOUS.
        skills: Names of the skills analysed.
        per_skill_capabilities: skill name -> sorted capability tags.
        aggregate_capabilities: Union of all capabilities across the set.
        risky_combinations: Cross-skill dangerous capability combos, each:
            {"capabilities": [...], "description": str, "contributors": {cap: [skills]}}.
        policy_violations: Capabilities the agent policy forbids, each:
            {"capability": str, "contributors": [skills], "reason": str}.
        individually_flagged: Skills that vet as REVIEW/MALICIOUS on their own.
        explanation: Human-readable summary.
    """
    verdict: str
    skills: list[str] = field(default_factory=list)
    per_skill_capabilities: dict[str, list[str]] = field(default_factory=dict)
    aggregate_capabilities: list[str] = field(default_factory=list)
    risky_combinations: list[dict] = field(default_factory=list)
    policy_violations: list[dict] = field(default_factory=list)
    individually_flagged: list[dict] = field(default_factory=list)
    explanation: str = ""

    @property
    def is_safe(self) -> bool:
        return self.verdict == "SAFE"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "skills": self.skills,
            "per_skill_capabilities": self.per_skill_capabilities,
            "aggregate_capabilities": self.aggregate_capabilities,
            "risky_combinations": self.risky_combinations,
            "policy_violations": self.policy_violations,
            "individually_flagged": self.individually_flagged,
            "explanation": self.explanation,
        }

    def __repr__(self) -> str:
        return (
            f"CompositionRisk(verdict={self.verdict}, skills={len(self.skills)}, "
            f"risky_combos={len(self.risky_combinations)}, "
            f"policy_violations={len(self.policy_violations)})"
        )


def _normalize_skill(
    item: Any, guard: Optional[SkillVetGuard], use_llm: bool
) -> tuple[str, set[str], Optional[str]]:
    """
    Normalize one skillset input to (name, capabilities, individual_verdict).

    Accepts a SkillVetResult, a dict with 'capabilities' (+ optional 'name'/'verdict'),
    or a path/str (which is vetted via SkillVetGuard).
    """
    if isinstance(item, SkillVetResult):
        return item.skill_name or "unnamed", set(item.capabilities), item.verdict

    if isinstance(item, dict) and "capabilities" in item:
        return (
            item.get("name") or "unnamed",
            set(item["capabilities"]),
            item.get("verdict"),
        )

    if isinstance(item, (str, Path)):
        g = guard or SkillVetGuard(use_llm=use_llm)
        result = g.vet(skill_path=item)
        return result.skill_name or str(item), set(result.capabilities), result.verdict

    raise TypeError(
        f"Cannot interpret skillset item of type {type(item).__name__}: "
        "pass a SkillVetResult, a dict with 'capabilities', or a path."
    )


def check_skillset(
    skills: list[Any],
    *,
    policy: Any = None,
    agent: Optional[str] = None,
    use_llm: bool = False,
) -> CompositionRisk:
    """
    Analyse a set of skills for compositional risk + capability-policy violations.

    Args:
        skills: List of skills — SkillVetResult objects, dicts with 'capabilities',
            or paths to skill directories/files (which get vetted).
        policy: Optional Policy object (or AgentPolicy) for capability isolation.
        agent: Agent name to resolve in `policy` (ignored if policy is an AgentPolicy).
        use_llm: Run the LLM judge when vetting paths. Default False.

    Returns:
        CompositionRisk.
    """
    guard = SkillVetGuard(use_llm=use_llm) if any(
        isinstance(s, (str, Path)) for s in skills
    ) else None

    per_skill: dict[str, set[str]] = {}
    individually_flagged: list[dict] = []
    for item in skills:
        name, caps, verdict = _normalize_skill(item, guard, use_llm)
        # Disambiguate duplicate names so contributor maps stay correct.
        if name in per_skill:
            suffix = 2
            while f"{name}#{suffix}" in per_skill:
                suffix += 1
            name = f"{name}#{suffix}"
        per_skill[name] = caps
        if verdict in ("REVIEW", "MALICIOUS"):
            individually_flagged.append({"skill": name, "verdict": verdict})

    aggregate: set[str] = set().union(*per_skill.values()) if per_skill else set()

    # --- cross-skill dangerous combinations ---
    risky_combinations: list[dict] = []
    for combo, description in DANGEROUS_COMBOS:
        if not combo.issubset(aggregate):
            continue
        # Skip combos already fully held by one skill — that's intra-skill (P0's job).
        if any(combo.issubset(caps) for caps in per_skill.values()):
            continue
        contributors = {
            cap: sorted(n for n, caps in per_skill.items() if cap in caps)
            for cap in sorted(combo)
        }
        risky_combinations.append({
            "capabilities": sorted(combo),
            "description": description,
            "contributors": contributors,
        })

    # --- memory poisoning vector: memory_write + any other skill ---
    if _MEMORY_POISON_CAP in aggregate and len(per_skill) > 1:
        writers = sorted(n for n, caps in per_skill.items() if _MEMORY_POISON_CAP in caps)
        others = [n for n in per_skill if n not in writers]
        if others:
            risky_combinations.append({
                "capabilities": [_MEMORY_POISON_CAP],
                "description": (
                    "memory-poisoning vector (a skill persists content that any other "
                    "instruction-following skill may later act on)"
                ),
                "contributors": {_MEMORY_POISON_CAP: writers},
            })

    # --- per-agent capability isolation (blocked at install) ---
    policy_violations: list[dict] = []
    agent_policy = _resolve_agent_policy(policy, agent)
    if agent_policy is not None:
        for cap in agent_policy.capability_violations(aggregate):
            policy_violations.append({
                "capability": cap,
                "contributors": sorted(n for n, caps in per_skill.items() if cap in caps),
                "reason": "capability not permitted by agent policy",
            })

    verdict = _rollup(individually_flagged, risky_combinations, policy_violations)
    explanation = _explain(verdict, risky_combinations, policy_violations, individually_flagged)

    return CompositionRisk(
        verdict=verdict,
        skills=list(per_skill.keys()),
        per_skill_capabilities={n: sorted(c) for n, c in per_skill.items()},
        aggregate_capabilities=sorted(aggregate),
        risky_combinations=risky_combinations,
        policy_violations=policy_violations,
        individually_flagged=individually_flagged,
        explanation=explanation,
    )


def _resolve_agent_policy(policy: Any, agent: Optional[str]):
    """Resolve a Policy/AgentPolicy/None into an AgentPolicy (or None)."""
    if policy is None:
        return None
    # AgentPolicy already?
    if hasattr(policy, "capability_violations"):
        return policy
    # Policy object — look up the agent.
    if hasattr(policy, "get_agent_policy"):
        return policy.get_agent_policy(agent or "")
    return None


def _rollup(individually_flagged, risky_combinations, policy_violations) -> str:
    if policy_violations or any(f["verdict"] == "MALICIOUS" for f in individually_flagged):
        return "MALICIOUS"
    if risky_combinations or individually_flagged:
        return "REVIEW"
    return "SAFE"


def _explain(verdict, risky_combinations, policy_violations, individually_flagged) -> str:
    if verdict == "SAFE":
        return "No compositional risk: capability set is benign and policy-compliant."
    parts = []
    if policy_violations:
        caps = ", ".join(v["capability"] for v in policy_violations)
        parts.append(f"policy forbids capabilities unlocked by this set: {caps}")
    if risky_combinations:
        parts.append(
            f"{len(risky_combinations)} dangerous cross-skill combination(s): "
            + "; ".join(c["description"] for c in risky_combinations[:3])
        )
    mal = [f["skill"] for f in individually_flagged if f["verdict"] == "MALICIOUS"]
    rev = [f["skill"] for f in individually_flagged if f["verdict"] == "REVIEW"]
    if mal:
        parts.append(f"individually malicious skill(s): {', '.join(mal)}")
    if rev:
        parts.append(f"individually flagged for review: {', '.join(rev)}")
    return f"{verdict} — " + "; ".join(parts) + "."
