"""Tests for the results spine (`utils/results.py`).

The load-bearing behaviour is STALENESS. A staleness check that cannot fail is worse than none,
because it reports every row as current — so most of what follows is about making it fail: changed
content, moved path, deleted path. The `unattributed` state gets its own tests because collapsing
it into `stale` would let a genuinely stale row hide among rows that were merely never
instrumented.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import results as R  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    """A fake tree with one 'step' file, so hashes are computed over content we control."""
    (tmp_path / "steps").mkdir()
    (tmp_path / "steps" / "run.py").write_text("print('v1')\n")
    return tmp_path


def _row(repo, **kw):
    row = R.build_row(
        topic="prompt-injection",
        recipe="qwen_injection",
        task="leaderboard",
        metrics={"mean_recall": 0.85},
        steps=["steps/run.py"],
        **kw,
    )
    row["steps_hash"] = R.steps_hash(row["steps"], repo)  # rehash against the fake tree
    return row


class TestRowShape:
    def test_required_fields_present(self, repo):
        row = _row(repo)
        for k in R.REQUIRED:
            assert k in row, k
        assert row["provenance"] == R.RECORDED

    def test_run_id_follows_the_filename_convention(self, repo):
        row = _row(repo, when="2026-07-26T19:00:00Z")
        assert row["run_id"] == "qwen_injection-leaderboard-20260726T190000Z"

    def test_append_rejects_an_incomplete_row(self, tmp_path):
        with pytest.raises(ValueError, match="missing required field"):
            R.append({"run_id": "x"}, tmp_path / "RESULTS.jsonl")

    def test_append_then_load_round_trips(self, repo, tmp_path):
        p = tmp_path / "RESULTS.jsonl"
        R.append(_row(repo), p)
        R.append(_row(repo), p)
        rows = R.load(p)
        assert len(rows) == 2
        assert rows[0]["metrics"] == {"mean_recall": 0.85}

    def test_load_of_a_missing_file_is_empty_not_an_error(self, tmp_path):
        assert R.load(tmp_path / "nope.jsonl") == []

    def test_metrics_are_not_normalised(self, repo):
        """The survey found no common metric schema; the spine must carry arbitrary shapes."""
        odd = {"latency_ms": {"p50": 0.03, "p99": 13.05}, "per_class": [1, 2], "note": None}
        row = R.build_row(
            topic="overhead", recipe="bench", task="latency", metrics=odd, steps=["steps/run.py"]
        )
        assert json.loads(json.dumps(row))["metrics"] == odd


class TestStaleness:
    def test_unchanged_code_is_ok(self, repo):
        state, reason = R.status(_row(repo), repo)
        assert (state, reason) == ("ok", "")

    def test_CHANGED_CODE_IS_STALE(self, repo):
        """The whole point. If this ever passes as 'ok', the spine is decorative."""
        row = _row(repo)
        (repo / "steps" / "run.py").write_text("print('v2')\n")  # one byte of behaviour changed
        state, reason = R.status(row, repo)
        assert state == "stale"
        assert "changed" in reason

    def test_deleted_step_is_stale_and_names_the_path(self, repo):
        row = _row(repo)
        (repo / "steps" / "run.py").unlink()
        state, reason = R.status(row, repo)
        assert state == "stale"
        assert "steps/run.py" in reason

    def test_moved_step_is_stale(self, repo):
        """Renames matter: the recipes/ migration moves every path, and that IS a change."""
        row = _row(repo)
        (repo / "recipes").mkdir()
        (repo / "steps" / "run.py").rename(repo / "recipes" / "run.py")
        assert R.status(row, repo)[0] == "stale"

    def test_unattributed_is_not_stale(self, repo):
        row = R.unattributed_row(
            topic="effect-boundary", recipe="legacy", task="coverage", artifact="results/x.json"
        )
        state, _ = R.status(row, repo)
        assert state == R.UNATTRIBUTED
        assert state != "stale"

    def test_unattributed_row_carries_no_invented_provenance(self, repo):
        row = R.unattributed_row(
            topic="effect-boundary", recipe="legacy", task="coverage", artifact="results/x.json"
        )
        assert row["steps"] == []
        assert row["steps_hash"] is None
        assert row["git_sha"] is None


class TestStepsHash:
    def test_order_independent(self, repo):
        (repo / "steps" / "b.py").write_text("b\n")
        a = R.steps_hash(["steps/run.py", "steps/b.py"], repo)
        b = R.steps_hash(["steps/b.py", "steps/run.py"], repo)
        assert a == b

    def test_content_not_mtime(self, repo):
        """Rewriting identical bytes must NOT change the hash, or every row goes stale on touch."""
        before = R.steps_hash(["steps/run.py"], repo)
        (repo / "steps" / "run.py").write_text("print('v1')\n")
        assert R.steps_hash(["steps/run.py"], repo) == before

    def test_a_directory_hashes_over_its_contents(self, repo):
        """Needed once a recipe directory is named directly instead of individual files."""
        before = R.steps_hash(["steps"], repo)
        (repo / "steps" / "extra.py").write_text("x\n")
        assert R.steps_hash(["steps"], repo) != before

    def test_missing_path_does_not_raise(self, repo):
        assert R.steps_hash(["steps/absent.py"], repo).startswith("sha256:")
