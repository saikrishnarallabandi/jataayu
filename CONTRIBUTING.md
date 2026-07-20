# Contributing

## Setup

```bash
pip install -e ".[dev]"
pytest -q          # ~1,070 tests, ~16s, no network or GPU required
ruff check jataayu tests examples demo benchmarks training
ruff format --check jataayu tests examples demo benchmarks training
python examples/quickstart.py   # the README's Quick Start, executable and self-asserting
```

All four run in CI on Python 3.10 / 3.11 / 3.12.

## Where things live

| Path | What |
|------|------|
| `jataayu/` | The package. `core/` is primitives (effect boundary, taint, audit); `guards/` are the layers built on them. |
| `tests/` | Unit suite. Fast, offline, deterministic. |
| `examples/` | User-facing, runnable. `quickstart.py` asserts everything the README's Quick Start teaches, and CI runs it — change a documented behavior and it fails there. Keep it out of `tests/`: it is written to be read. |
| `benchmarks/` | Scores the library against *external* datasets. Slow, may need network or a GPU. Not part of CI. |
| `demo/` | The HuggingFace Space source. |
| `training/` | Detector training pipelines. |

The distinction between `tests/` and `benchmarks/` is load-bearing: a test asserts a fixed
behavior and fails; a benchmark reports a number and is read by a human.

## What a good change looks like

**The guarantee lives at the effect boundary, not in the detector.** Patches that improve the
regex tier are welcome, but the project's claim is that action authorization is what holds when
detection fails. A change that makes the detector look better while weakening the boundary is
going the wrong way.

**Bring a measurement, not an assertion.** If you claim a change improves detection, run the
relevant benchmark before and after and put both numbers in the PR. `benchmarks/README.md`
explains how. Numbers without a committed dataset and a runnable command are not reviewable.

**Say what the change does *not* cover.** The most useful part of a security patch is often its
stated limits. This repo documents its own failures (see the over-defense section in
`README.md`) — write in that register.

## Evaluation changes

Two rules, both learned the hard way:

1. **Do not reimplement a scorer.** If a canonical implementation exists, import it. Training and
   evaluation must compute the same thing or the numbers drift silently.
2. **Do not select on a single metric.** Recall at a fixed FPR rewards a model that keys on
   trigger words. Counterfactual paired accuracy is what penalises that shortcut. A checkpoint
   that wins on one and loses on the other is not an improvement.

If you add a benchmark, it needs a committed dataset (or a deterministic generator), a single
command that reproduces the result, and output in the same JSON shape as its neighbours.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Style

Ruff is the only required style tool: use `ruff check ...` for linting and `ruff format ...` for formatting. There is no separate style guide. Match the surrounding code. Comments
should explain *why*, not restate the line — the existing source is the reference for the level
of comment the project expects.
