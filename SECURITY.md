# Security Policy

Jataayu is a security library. If it fails, it fails quietly and something else gets
through — so we would much rather hear about a weakness than not.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's [private vulnerability reporting](https://github.com/saikrishnarallabandi/jataayu/security/advisories/new)
(Security tab → Report a vulnerability). If that is unavailable to you, email
**srallaba.research@gmail.com** with `[jataayu security]` in the subject.

What helps:

- The input that triggers it, verbatim, and the surface it was checked against
- What you expected versus what happened
- Whether LLM mode was enabled, and which backend
- The version (`jataayu --version` or `jataayu.__version__`)

You will get an acknowledgement within **3 working days** and an assessment within **10**.
This is a single-maintainer project, so those are honest targets rather than an SLA.

## What counts as a vulnerability here

This project's threat model is an attacker who controls *content* an agent processes, not
one who controls the agent's own code or configuration.

**In scope:**

- A **bypass**: input that carries an attack past a guard that should have caught it —
  particularly one that generalises rather than a single crafted string.
- A **fail-open**: any path where a guard returns `allow` on error, on an unrecognized
  input, or on a malformed policy. Fail-open in a reference monitor is the bug class we
  care most about.
- **Effect-boundary escape**: a tool name, argument shape, or provenance path that reaches
  a higher-severity effect than it is classified as.
- **Leakage through the guard itself** — the outbound guard emitting the very thing it was
  configured to protect.
- Policy parsing that silently grants more than the policy text says.

**Out of scope** (real limitations, documented, not vulnerabilities):

- The pattern/regex tier missing a novel attack. It is deliberately the weakest layer and
  the README says so; report a *class* of miss, not an individual string.
- Detector false negatives against an adaptive attacker. Detection is documented as a
  defence-in-depth signal, never a sole control.
- Anything requiring the attacker to already control the policy file, environment, or
  process.
- Denial of service via pathologically large input.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | ✅ |
| < 0.3 | ❌ |

Only the latest minor release receives fixes. There is no long-term support branch.

## Disclosure

Coordinated disclosure. We will agree a date with you, and default to publishing once a fix
is released. Credit is given unless you ask us not to. There is no bug bounty — this is an
unfunded project, and we would rather be honest about that than imply otherwise.

## A note on scope honesty

Jataayu is a wrapper and a reference monitor, not a guarantee. Its own documentation states
where it is weak. A report that shows a documented weakness is worse than documented is
valuable; a report that restates a documented weakness is not a finding, though we are still
glad you looked.
