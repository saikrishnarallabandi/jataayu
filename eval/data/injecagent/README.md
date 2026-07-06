# InjecAgent data (external, not vendored)

The Tier-3 effect-boundary evaluation (`eval/run_effect_boundary_injecagent.py`,
results in `eval/results/effect_boundary_injecagent.json`) replays the public
**InjecAgent** benchmark (Zhan et al., ACL 2024 Findings, arXiv:2403.02691). We do
**not** vendor its corpus here (it is released under its own license); obtain it and
drop the files into this directory:

```bash
git clone https://github.com/uiuc-kang-lab/InjecAgent
cp InjecAgent/data/test_cases_*.json eval/data/injecagent/
```

Expected files (the runner reads these):

```
test_cases_dh_base.json      test_cases_dh_enhanced.json
test_cases_ds_base.json      test_cases_ds_enhanced.json
```

Then reproduce:

```bash
python eval/run_effect_boundary_injecagent.py        # defaults to this dir
# or: python eval/run_effect_boundary_injecagent.py --data-dir <path>
```

The run is deterministic (decisions/metrics byte-identical across runs; only
wall-clock latency varies).
