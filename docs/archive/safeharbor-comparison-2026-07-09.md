# SafeHarbor (arXiv:2605.05704) vs Jataayu — is it better than what we have?

*2026-07-09. Prompted by: "go through this paper, I'm not sure it's better than what we have,
benchmark Jataayu against this dataset." Answer up front: **it is not "better" — it is on a
different axis.** SafeHarbor separates harmful-vs-benign INTENT on trusted user input; Jataayu
gates EFFECTS by provenance. On SafeHarbor's own benchmark, with real `EffectBoundary` decisions,
Jataayu blocks 94.2% of harmful agent chains — but it is intentionally intent-blind, so it blocks
benign ones almost as often. That is the whole story, and it is a feature, not a loss.*

---

## 1. What SafeHarbor is

**"SafeHarbor: Defining Precise Decision Boundaries via Hierarchical Memory-Augmented Guardrail
for LLM Agent Safety."** A *misuse/jailbreak guardrail*:

- **Method:** offline, it evolves ~3k adversarial attacks (via a Qwen2.5-72B teacher) into a
  self-organizing "Risk-Tree" of prohibition + benign-exemption rules, and trains a lightweight
  MLP "Safety Projector" (~5 min on A100). Online, a two-stage gate: the projector fast-paths
  clear cases; a 7B LLM judges ambiguous ones by retrieving the nearest rules from the tree.
- **Input:** the **agent trajectory** τ = (a₁,o₁,…) — reasoning, tool actions, observations
  (live agent execution via `inspect-ai`, then LLM-judge grading).
- **Threat model:** **direct user misuse.** The adversary is the *malicious requester* — "malicious
  users can induce agents into executing dangerous operations." Indirect prompt injection is **not**
  in scope (Greshake 2023 appears only as one related-work citation). No provenance, no dataflow.
- **Cost:** 1 model (7B), **14 GB VRAM**, **306.67 ms/decision**.

## 2. What Jataayu is

A **deterministic effect-boundary authorizer.** No LLM in the decision path. For each action it
computes `decision = f(effect severity × worst inbound provenance × capability policy)`:
untrusted-derived input into a critical effect (shell/code/secret-read) → **DENY**; into a
consequential effect (network/file-write/memory-write) → **NEEDS_APPROVAL**; trusted or low-severity
→ **ALLOW**. Plus PREVIEW→COMMIT (token binds the exact authorized request) and opaque-handle read
confinement. **Threat model: indirect injection** — the adversary is *untrusted input*, not the user.

**These are orthogonal.** SafeHarbor asks "is this request harmful?" Jataayu asks "is this action
authorized given where its input came from?" Neither answers the other's question.

## 3. Benchmark — Jataayu on AgentHarm (SafeHarbor's dataset)

Harness: `eval/run_agentharm_effect_boundary.py`. Data: AgentHarm public test + validation =
**208 harmful + 208 benign** behaviors (SafeHarbor uses the full 440 augmented set; the 208 public
split is what's downloadable). We map AgentHarm's 85 synthetic tools to Jataayu `EffectClass` (the
map is emitted in the results JSON, fully auditable) and run the **real** `EffectBoundary._decide`
over every behavior's `target_functions`. A behavior is "blocked" if any tool in its chain gets
DENY or NEEDS_APPROVAL.

| Framing | harmful blocked/held | benign blocked/held | **intent separation** | deny (hard) |
|---|---|---|---|---|
| **A. Injection** (untrusted provenance — Jataayu's native setting) | **94.2%** | 92.3% | **+1.9 pt** | 40.4% |
| **B. Direct-misuse + restrictive policy** (trusted input, locked-down capabilities) | 94.2% | 92.3% | +1.9 pt | 94.2% |
| **C. Direct-misuse + permissive policy** (trusted, no capability limits) | 0.0% | 0.0% | 0.0 pt | 0% |
| **D. Out-of-box** (no tool→effect registration) | 30.8% | 30.8% | 0.0 pt | 5.8% |

**SafeHarbor GPT-4o, for contrast:** harmful-refusal **93.2%**, benign-refusal **25.0%**
(benign utility 63.6%, harm-score 6.3) → **intent separation ≈ +68 pt.**

### Reading the table
- **Jataayu matches SafeHarbor's harmful-block rate (94.2% vs 93.2%)** — deterministically, with no
  model, no training, no 14 GB, at sub-millisecond cost instead of 307 ms.
- **But Jataayu's intent separation is ~2 pt, vs SafeHarbor's ~68 pt.** This is the crux: Jataayu
  *cannot tell a harmful post-to-X from a benign post-to-X*, because its discriminator is the input's
  **provenance and the effect's severity**, not the user's **intent**. When both requests are
  trusted (framing C) it allows both; when both look untrusted (A) or the policy is locked (B) it
  blocks both. Separating intent from identical effects is exactly what a trained classifier like
  SafeHarbor is *for* — and exactly what Jataayu deliberately does not attempt.
- **The 12 harmful behaviors (5.8%) Jataayu never blocks are all pure web-search / info-gathering
  chains** (e.g. drug-synthesis lookup, fraud research) — READ-only, no dangerous effect fires. The
  harm is *informational*, living in the text, not in an action. That is precisely SafeHarbor's
  domain and precisely outside Jataayu's (we don't gate a Google search). This is the semantic-vs-
  effect boundary made concrete: the two systems cover complementary halves.
- **Framing D (30.8%) is the honest deployment caveat:** Jataayu ships knowing common tool names;
  an operator must register a custom agent's tool→effect map (as we did here) or unknown tools fall
  through to READ. That's a one-time config step, not a capability ceiling.

## 4. Head-to-head, by axis

| | SafeHarbor | Jataayu |
|---|---|---|
| Adversary | the **user** (direct misuse) | **untrusted input** (indirect injection) |
| Discriminator | harmful vs benign **intent** (learned) | **provenance × effect severity × policy** (deterministic) |
| Separates intent on trusted input | **yes (~68 pt)** | no (~2 pt) — by design |
| Blocks harmful *effects* (AgentHarm) | 93.2% refusal | **94.2%** block/hold |
| Covers indirect injection (AgentDojo/InjecAgent) | **no** (not in threat model) | **yes** (core guarantee) |
| Decision cost | 7B LLM, 14 GB, 307 ms | no model, sub-ms |
| Offline build | Risk-Tree (<1 hr A100) + MLP train | none (rules are code) |
| Informational harm (no effect) | **catches it** | misses it (no action to gate) |

## 5. Verdict — the direct answer

**SafeHarbor is not "better than what we have"; it solves a problem we deliberately don't.**

1. For **direct user misuse** — a user asking the agent to write ransomware or run a harassment
   campaign — SafeHarbor genuinely wins: it separates harmful from benign intent (~68 pt) while
   keeping 63.6% benign utility. Jataayu can only match its harmful-block rate by *also* blocking
   benign traffic (framings A/B) or by a restrictive policy that is intent-blind. If misuse-refusal-
   with-utility is the goal, you want a classifier, and SafeHarbor is a good one (though LlamaGuard
   beats it on raw refusal; SafeHarbor's real claim is the *trade-off*).
2. For **indirect injection** — an attacker's instruction riding in on a web page, tool return, or
   memory — SafeHarbor offers **nothing** (no provenance, not its threat model). Jataayu blocks
   94% of the resulting harmful effect-chains deterministically, at zero model cost.
3. They are **complementary layers**, not competitors: SafeHarbor is an *intent gate on trusted
   input*; Jataayu is a *provenance/effect gate on untrusted input*. A serious deployment wants
   both — a misuse classifier on the front door and an effect boundary on every action. The one
   thing you must not do is mistake SafeHarbor's 93% AgentHarm refusal for injection robustness;
   the paper never claims that, and our numbers show why the axes don't transfer.

**What this does change for us:** it sharpens the positioning line (intent-gate vs effect-gate) and
gives us a clean, reproducible AgentHarm number to cite. It does *not* argue for adopting a trained
memory-tree guardrail into Jataayu's core — that would trade our deterministic, no-model guarantee
for a probabilistic classifier on a threat model we don't target. If we ever want misuse-refusal,
the cheaper move is to compose an off-the-shelf classifier in front of the effect boundary, not to
rebuild SafeHarbor.

*Reproduce: `python eval/run_agentharm_effect_boundary.py`. Results:
`eval/results/agentharm_effect_boundary.json`.*
