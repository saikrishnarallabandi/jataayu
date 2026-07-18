# Benchmarks

Scores jataayu against *external*, labeled datasets. This is separate from `tests/`, which is
the library's own unit suite — these runners download or generate data, take minutes to hours,
and report metrics rather than pass/fail.

## Layout

| Path | What |
|------|------|
| `run_*.py` | One runner per benchmark. Each is standalone; usage is in its module docstring. |
| `data/` | Corpora. `gen_*.py` regenerate the synthetic ones deterministically; the rest are downloaded. |
| `results/` | Saved JSON output, one file per run. Checked in — these are the numbers quoted in the README and paper. |
| `agentdojo/` | AgentDojo integration (`jataayu_defense.py`) plus sweep drivers. |
| `qwen_injection/` | Scoring harness for the fine-tuned injection detector variants. |

## Families

- **Injection detection** — `run_injection_bench.py` (fast path vs. public injection datasets),
  `run_slowpath_bench.py` (LLM judge), `run_detector_headtohead.py` (jataayu vs. third-party
  detectors), `run_lodo_fastpath.py` (leave-one-dataset-out).
- **Effect boundary** — `run_effect_boundary_bench.py` (Tier 1) plus `_tier2`, `_edges`,
  `_injecagent`, `run_agentharm_effect_boundary.py`, `run_semantic_vs_effect.py`,
  `run_synthetic_bias_effect.py`.
- **Egress / privacy** — `run_egress_bench.py`, `run_outbound_privacy_bench.py`.
- **Memory poisoning** — `run_memory_poison_bench.py`.
- **Composition** — `run_composition_bench.py` (individually-plausible skill *sets*).
- **Agent end-to-end** — `agentdojo/run_agentdojo.py`, `run_injecagent_bench.py`.

## Running one

The effect-boundary benchmark is deterministic and needs no model or network:

```bash
python benchmarks/run_effect_boundary_bench.py \
  --dataset benchmarks/data/effect_boundary_v1.jsonl \
  --baselines none detector effect both \
  --out benchmarks/results/effect_boundary_v1.json --json
```

It prints APR (attack prevention rate), TUR (task utility retained) and FBR (false-block rate)
per baseline, and writes the same to `--out`.

Runners that hit Hugging Face or an LLM endpoint need extra dependencies; `.venv/` (AgentDojo
stack) and `.venv-hf/` (Hugging Face datasets) are local, gitignored virtualenvs for those.
