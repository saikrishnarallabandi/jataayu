"""Median-of-runs latency, so a published median is what the command actually produces.

Run-to-run spread is real at sub-millisecond scale, so the README quotes a median over
several runs of each benchmark command. `--repeat N` on the runners exists to produce that
number: each run is summarized on its own, and the reported figure is the median of the
per-run statistics — NOT the statistics of a pooled sample, which would blend the runs and
hide the dispersion.

With N=1 the median of one run is that run, so `median_of_runs` returns exactly what a
single pass reported before this existed.
"""
import statistics as st


def summarize(lat):
    """Per-run latency statistics from a list of per-call milliseconds."""
    s = sorted(lat)
    return {
        "mean": round(st.mean(lat), 4),
        "p50": round(st.median(lat), 4),
        "p99": round(s[max(0, int(len(s) * 0.99) - 1)], 4),
    }


def median_of_runs(runs):
    """Median of each statistic across per-run summaries from `summarize`.

    Carries the per-run values when there is more than one, so the artifact shows its own
    dispersion instead of just a point estimate.
    """
    out = {k: round(st.median([r[k] for r in runs]), 4) for k in ("mean", "p50", "p99")}
    if len(runs) > 1:
        out["per_run"] = runs
    return out
