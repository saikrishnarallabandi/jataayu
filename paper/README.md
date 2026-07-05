# Jataayu × AgentDojo — technical report

Academic-style report evaluating Jataayu's deterministic tool-output injection screen on the
AgentDojo benchmark (`workspace` suite, `important_instructions` attack, `qwen3.6:35b-a3b`),
and documenting a silent tool-call parse failure in AgentDojo's local-model adapter that
zeroes benchmark utility.

## Files

- `jataayu_agentdojo.tex` — the paper. **Self-contained**: compiles with `pdflatex` out of
  the box (pgfplots figure, `booktabs` table, inline `thebibliography`; no external `.bib`
  or image assets).
- `jataayu_agentdojo.pdf` — a pre-built copy for convenience.

## Build

```bash
pdflatex jataayu_agentdojo.tex
pdflatex jataayu_agentdojo.tex   # second pass resolves refs/citations
```

## Overleaf

Overleaf → New Project → **Import from GitHub** → this repo. Set the main document to
`paper/jataayu_agentdojo.tex`. It compiles unchanged (Overleaf's TeX Live has current
pgfplots).

## Headline result

| condition | util (no attack) | util (under attack) | ASR |
|---|---|---|---|
| baseline | 1.00 | 0.75 | 0.10 |
| Jataayu  | 1.00 | 1.00 | 0.00 |

Slice: 5 user tasks × 4 injection tasks. The defense drives attack-success to zero and
restores utility with no clean-task cost; the wins concentrate on the two tasks where the
baseline is hijacked. See the paper for the reproducibility caveat and limitations.
