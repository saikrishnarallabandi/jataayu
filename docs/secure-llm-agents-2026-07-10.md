# Toward Secure LLM Agents - Jataayu Notes

Date: 2026-07-10

Paper: **Toward Secure LLM Agents: Threat Surfaces, Attacks, Defenses, and Evaluation**
Link: https://arxiv.org/abs/2606.10749

Podcast: **SangrahaPods Episode 20: Agents Need Boundaries - Security as Systems**
Link: https://open.spotify.com/episode/0yVXmMWM4rnV2oDxiiz85b

## One-Line Read

This paper is a useful literature-map for the Jataayu thesis: LLM-agent security is no longer just
about filtering unsafe text. It is a systems problem across tools, memory, authority, persistent
state, provenance, monitoring, and multi-agent coordination.

## Why It Matters For Jataayu

The paper validates the shift from prompt-level defense to runtime surface control. Agents now read
from private and public sources, retain memory, call tools, write outbound messages, and delegate to
other agents. The hard security question is not "is this answer safe?" but "what surface is the
agent standing on, what context influenced it, and what effect is it about to cause?"

That maps directly to Jataayu's core bet:

- **Surface integrity:** every input, memory, tool result, and outbound message needs an audience
  and trust boundary.
- **Effect boundary:** dangerous actions should be gated before execution, using provenance and
  effect severity rather than final-answer classification.
- **Provenance-aware state:** memory is not just context; it is durable influence that can carry
  injection, privacy, and trust mistakes across turns.
- **Deployment-realistic evals:** benchmarks should measure tool calls, memory writes, exfil paths,
  and cross-agent propagation, not only whether the generated text looks benign.

## Product Takeaways

1. **Lead with "agents need boundaries."**
   The most public-friendly Jataayu message is that personal and enterprise agents need runtime
   judgment about surfaces: private DM, group chat, calendar, file, browser, memory, and outbound
   action. This is more concrete than "prompt-injection defense."

2. **Make provenance visible in the developer story.**
   The system should show why an action was allowed, blocked, or escalated: source surface, trust
   level, audience, memory influence, and effect severity. That audit trail is the moat.

3. **Treat memory as an attack and privacy surface.**
   Persistent memory can preserve poisoned instructions, stale facts, private preferences, and
   audience-specific context. Jataayu should distinguish temporary, private, group-local, and durable
   memory writes.

4. **Outbound is not just PII redaction.**
   The dangerous case is often a correct-looking answer sent to the wrong surface, or a link/tool
   output that becomes an exfil channel. Jataayu's outbound guard should keep evolving toward a
   full egress reference monitor.

5. **Evaluate effects, not vibes.**
   A useful Jataayu eval should ask: did a tool call happen, did memory change, did private context
   enter a shared surface, did a delegated agent inherit tainted state, and was a user approval
   boundary crossed?

## Positioning Language

Personal agents do not just need better reasoning. They need judgment about which surface they are
standing on.

Jataayu is the surface-integrity layer for agents: it watches what the agent touches, what context
influenced it, who the audience is, and whether the next effect is allowed.

## Follow-Up Work

- Mine the paper's taxonomy against Jataayu's current modules: inbound, outbound, egress, memory,
  skill vetting, effect boundary, and audit.
- Add a short comparison section to the broader literature review if the paper has a clean taxonomy
  worth reusing.
- Convert the podcast framing into a landing-page or README section only after the module mapping is
  precise enough to avoid sounding like generic agent-safety positioning.
