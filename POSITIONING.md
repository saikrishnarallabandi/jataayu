# Jataayu — Positioning & Path to Canonical Reference

Grounded in the actual repo state (v0.3.1, 435 passing tests, ~7,100 LOC) and the saved
`eval/` results. Written to be honest first — every claim below is backed by code or an eval
JSON in this repo, because "people cite this" only works if the claims survive scrutiny.

---

## 1. The one-line pitch
**Jataayu is a runtime authorization layer for tool-using AI agents: it gates the *action*, not the string.**

Longer: a deterministic effect-boundary that decides ALLOW / DENY / NEEDS_APPROVAL for every
consequential agent action from `input-provenance × effect-severity × capability-policy` —
plus defense-in-depth screening (inbound injection, outbound PII/exfiltration, skill vetting)
and replayable audit traces.

## 2. The category it owns (the strategic repositioning)
**Lead with the effect boundary. Demote the detector.**

The crowded, losable category is *prompt-injection detection* (string classifiers). Jataayu's
own evals show the regex tier is a weak general detector — ROC-AUC **0.63** on `deepset/prompt-injections`,
low recall (`eval/results/deepset_prompt-injections_unknown_fastpath.json`). Competing there
invites the comparison we lose.

The defensible, uncrowded category is **runtime action authorization** — "an agent read attacker-
controlled text; should this *tool call* be allowed to commit?" Jataayu's `effect_boundary.py`
answers that deterministically (no LLM, no flaky recall), with a `preview()→commit()` flow bound
by a hash `commit_token`. Almost nobody owns this as a named primitive. **This is the flag.**

Reframe the utility cost as intended behavior: on AgentDojo the defense drives attack-success to
0 while task utility drops 0.475→0.25 (`eval/results/agentdojo_workspace_..._full.json`). For a
*detector* that's a false-positive problem; for an *authorization layer* that's mostly the
NEEDS_APPROVAL path doing its job — converting silent unsafe execution into gated execution.
(We still owe an honest accounting of genuine false-DENYs and must drive them down — see §6.)

## 3. Who it's for
- Engineers shipping **tool-using / MCP agents** that touch email, money, files, repos, tickets — anything with irreversible effects.
- Teams that need **auditability**: a replayable trace of what the agent did and why it was allowed (`core/audit.py`, `SessionTrace`).
- Not for: chatbots with no tools/effects (there's no action to gate).

## 4. Honest capability claims (backed by code)
Say these — each maps to real, tested code:
- **Deterministic action gating** — `guards/effect_boundary.py`, `test_effect_boundary.py`. Provenance/effect typing, preview→commit, hash-bound token.
- **Cross-turn audit** — `core/audit.py`, `test_audit.py`. Deterministic trajectory review.
- **Outbound privacy + exfiltration egress guard** — `guards/outbound.py`, `guards/egress.py`. Catches data-carrying-URL / auto-fetched-image leaks (EchoLeak/AgentFlayer class).
- **Input normalization + taint tracking** — `core/normalize.py`, `core/taint.py`. NFKC/confusable fold, zero-width strip, recursive base64/hex/url decode, source→sink taint.
- **Skill / MCP supply-chain vetting** — `guards/skill_vet.py`, `guards/composition.py` (compositional analysis is deterministic).
- **MCP gateway** — `integrations/mcp_gateway.py`. Drop-in proxy that scans `tools/call`.
- **Capability policy as YAML** — `config/policy.py`, `examples/jataayu-policy.example.yml`.
- **399 tests, MIT, deterministic paths fully covered.**

## 5. What NOT to claim (guardrails)
- ❌ "Best-in-class prompt-injection detection." The evals say otherwise (ROC-AUC 0.63). Frame the regex tier as *defense-in-depth, explicitly the weakest layer* (the README already does this — keep it).
- ❌ The narrow "0.97→0.00 evasion" number as a general detection result. It's *space-out/leetspeak normalization on a synthetic set only*. Say that precisely.
- ❌ Anything about the LLM "slow path" being validated — it has no offline tests and depends on a live backend.
- ❌ Any arXiv stat not independently verified. The CHANGELOG already documents removing a fabricated stat and reconciling mis-cited figures — finish that sweep before publishing (several `2606.xxxxx` IDs need confirming).

## 6. Gap-to-canonical punch list (what makes it "the thing people cite")
Prioritized. Roughly the launch order.
1. **README repositioning** — lead with the effect boundary / action-authorization thesis; keep the detector honestly demoted. (Cheap, highest leverage.)
2. **Ship the effect-boundary benchmark as the *headline* result** — a runner that isolates the deterministic action-gating: attack-prevention vs utility-retained, on AgentDojo/InjecAgent. Own the yardstick for *authorization*, not detection. This is the durable, cite-able asset.
3. **Test + lint CI** — GitHub Actions running the 399 tests (+ ruff) on every PR. Today the only workflow deploys a webpage. Add a coverage badge.
4. **PyPI release** — `pip install jataayu`. Wheels already build in `dist/`; add a tagged release + publish workflow. Git-only install kills adoption.
5. **Runnable examples** — `examples/` has one YAML. Add: a real agent being attacked and defended end-to-end; a "wrap your agent in 10 lines" quickstart; a notebook.
6. **One framework adapter** — pick the highest-adoption target (LangChain or OpenAI-Agents or Anthropic tool-use) and ship a middleware/decorator. Today it only speaks MCP + a private host. DIY integration blocks reach.
7. **Drive down genuine false-DENYs** — quantify and reduce the legitimate-task hit the AgentDojo eval exposes; publish the honest before/after.
8. **Citation hygiene sweep** — verify every external reference; API-stability + CONTRIBUTING + semver commitment for reference status.
9. **API doc site** — docstrings are excellent; generate a real reference (the current Pages site is a landing page, not docs).

## 7. Launch sequence (feeds Austin flag + national/global reach from one body of work)
Each step is one artifact that serves the meetup *and* the world:
1. **Repositioned README + effect-boundary benchmark** → the substance.
2. **PyPI v0.4.0 + CI green** → adoptable, credible.
3. **Substack flagship post** — "Gate the action, not the string: runtime authorization for AI agents" — the thesis + the benchmark. (Owned channel already exists.)
4. **Cross-post** — HN / the agents ecosystem (national/global ring) and Austin Inno / Built In Austin (local ring).
5. **Talk it** — the AIEWF-tier and Austin-meetup version of the same thesis. Convert applied-to talks into invited ones.
6. **One framework adapter + demo** → turns readers into users; adoption is the global-recognition lever an H1B engineer can pull.

## 8. The measurable bet
Recognition follows a cited artifact. Targets, in order: PyPI installs → GitHub stars/forks →
external projects depending on jataayu → the effect-boundary benchmark cited by others → invited
(not applied) talks about it. That chain is what turns "a good repo" into "the Austin/national
applied-agents-security name."
