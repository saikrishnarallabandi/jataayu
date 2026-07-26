"""The results spine: one append-only row per run, in `RESULTS.jsonl` at the repo root.

WHY THIS EXISTS. A survey of every result file tracked in this repo (45 of them, across
`benchmarks/results/` and `training/injection_adapter/eval/results/`) found that **36 carry no
provenance at all** — no timestamp, no commit, no record of what produced them. Exactly one
records when it was generated; two more carry a timestamp only in their filename. So today the
question "is this number current, and what code produced it?" is unanswerable without archaeology,
and it has already cost real retractions: effect-boundary-v2's 83.9->98.2% turned out to be a fit
artifact, and a delimiter result reported as a headline did not replicate.

WHAT IT DOES NOT DO. It does not normalise metrics. The same survey found no common schema — the
most frequent key (`latency_ms`) appears in 16 of 44 files, `benchmark` in 13, `dataset` in 14 —
because a latency percentile, an ROC-AUC and an unrecognized-rate are not the same shape and
should not be forced into one. `metrics` is therefore a free-form dict, and `artifact` points at
the full result file. The spine carries IDENTITY and PROVENANCE; the artifact carries the numbers.

STALENESS IS THE POINT. Each row records the paths whose content defines the run (`steps`) and a
hash over them. A row whose code has changed since it ran is STALE, and the leaderboard says so
instead of presenting it as current. Recording `steps` per row, rather than hashing a fixed
directory, is what lets this survive the move to `recipes/<topic>/` — the paths change, the
mechanism does not.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "RESULTS.jsonl"

#: A row that was written by a runner and carries its own provenance.
RECORDED = "recorded"
#: A row backfilled from a result file that predates the spine. Its `steps` are not known, so its
#: staleness is NOT computable — it is never reported as current, and never as stale either.
UNATTRIBUTED = "unattributed"

REQUIRED = ("run_id", "topic", "recipe", "task", "metrics", "provenance", "created_utc")


def utc_now() -> str:
    """ISO-8601 Z. Storage is always UTC; only human-facing output converts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_id(recipe: str, task: str, when: str | None = None) -> str:
    """`<recipe>-<task>-<compact UTC>`, matching the convention already in result filenames."""
    stamp = (when or utc_now()).replace("-", "").replace(":", "")
    return f"{recipe}-{task}-{stamp}"


def steps_hash(steps, root: Path | None = None) -> str:
    """sha256 over the CONTENT of each step path, order-independent.

    Missing paths hash as a sentinel rather than raising, so a row whose code was deleted or moved
    reads as stale instead of crashing the leaderboard. Directories hash over the files inside
    them, sorted, so a recipe directory can be named directly once recipes/ exists.
    """
    root = root or REPO_ROOT
    h = hashlib.sha256()
    for rel in sorted(steps):
        p = root / rel
        files = sorted(q for q in p.rglob("*") if q.is_file()) if p.is_dir() else [p]
        for q in files:
            h.update(str(q.relative_to(root)).encode())
            h.update(q.read_bytes() if q.exists() else b"\0MISSING\0")
    return "sha256:" + h.hexdigest()


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def build_row(
    *,
    topic: str,
    recipe: str,
    task: str,
    metrics: dict,
    steps,
    model: str | None = None,
    artifact: str | None = None,
    when: str | None = None,
) -> dict:
    """Assemble a `recorded` row. Callers pass the paths that DEFINE the run as `steps`."""
    created = when or utc_now()
    steps = list(steps)
    return {
        "run_id": run_id(recipe, task, created),
        "topic": topic,
        "recipe": recipe,
        "task": task,
        "model": model,
        "metrics": metrics,
        "artifact": artifact,
        "steps": steps,
        "steps_hash": steps_hash(steps),
        "git_sha": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "created_utc": created,
        "provenance": RECORDED,
    }


def unattributed_row(*, topic: str, recipe: str, task: str, artifact: str, **kw) -> dict:
    """A row for a result file that predates the spine.

    It gets no `steps` and no `steps_hash` ON PURPOSE. Inventing a plausible producer for a file
    whose lineage is unknown is worse than recording the gap, because it converts an admitted
    unknown into an assertion nobody will re-check.
    """
    created = kw.pop("when", None) or utc_now()
    return {
        "run_id": run_id(recipe, task, created),
        "topic": topic,
        "recipe": recipe,
        "task": task,
        "model": kw.pop("model", None),
        "metrics": kw.pop("metrics", {}),
        "artifact": artifact,
        "steps": [],
        "steps_hash": None,
        "git_sha": None,
        "git_dirty": None,
        "created_utc": created,
        "provenance": UNATTRIBUTED,
    }


def append(row: dict, path: Path | None = None) -> dict:
    missing = [k for k in REQUIRED if k not in row]
    if missing:
        raise ValueError(f"row is missing required field(s): {missing}")
    path = path or RESULTS
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def load(path: Path | None = None) -> list[dict]:
    path = path or RESULTS
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def status(row: dict, root: Path | None = None) -> tuple[str, str]:
    """(state, reason) where state is 'ok', 'stale', or 'unattributed'.

    'unattributed' is deliberately NOT 'stale': the row's code is unknown, not known-changed.
    Collapsing the two would let a genuinely stale row hide among rows that were merely never
    instrumented.
    """
    if row.get("provenance") == UNATTRIBUTED or not row.get("steps"):
        return UNATTRIBUTED, "no steps recorded; staleness is not computable"
    root = root or REPO_ROOT
    missing = [s for s in row["steps"] if not (root / s).exists()]
    if missing:
        return "stale", f"step path(s) no longer exist: {', '.join(sorted(missing))}"
    now = steps_hash(row["steps"], root)
    if now != row.get("steps_hash"):
        return "stale", "producing code changed since this run"
    return "ok", ""
