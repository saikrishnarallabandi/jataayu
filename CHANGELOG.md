# Changelog

All notable changes to jataayu are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-28

### Added
- **Execution-context surfaces + skill vetting** — guards are now surface-aware, grading
  threats by where an action actually takes effect rather than the final answer (arXiv 2026 P0).
- **Compositional skillset analysis + capability isolation** — detects unsafe combinations of
  individually-safe skills (arXiv 2026 P1).
- **Always-on credential redaction** with auto-populated redaction output on the outbound path.
- **Evaluation suite** (`eval/`) — reproducible benchmarks against the public
  `deepset/prompt-injections` dataset (662 samples):
  - Fast path: ~0.97 precision, ~0.5% false-block, sub-millisecond per check.
  - Fast+LLM slow path: recall ~0.27 → ~0.50 (AUC 0.63 → 0.81), precision ~0.98.
  - `run_injection_bench.py` (fast path) and `run_slowpath_bench.py` (LLM slow path,
    points at any tailnet/local ollama endpoint).

### Changed
- Build now uses the standard `setuptools.build_meta` backend.

### Notes
- 106 detection patterns (68 inbound + 38 outbound); 293 tests passing.
- Still **0.2.0 alpha** — install from GitHub, not yet published to PyPI.
