import json

from jataayu.observability import summarize
from jataayu.runtime import dispatch


def test_report_separates_traffic_and_revisions_and_counts_bad_records():
    def row(id, **kw):
        return json.dumps(
            {
                "kind": "decision_receipt",
                "schema_version": 1,
                "decision_id": id,
                "traffic": "live",
                "mode": "shadow",
                "core_fingerprint": "first",
                "duration_ms": 10,
                **kw,
            }
        )

    report = summarize(
        [
            row("one"),
            row("one"),
            row("two", traffic="synthetic"),
            row("three", core_fingerprint="second"),
            "{broken",
            "{}",
        ]
    )
    assert len(report["groups"]) == 3
    assert report["excluded"] == {
        "duplicate_receipt_id": 1,
        "malformed_json": 1,
        "legacy_or_unrelated": 1,
    }
    assert all(g["events"] == 1 for g in report["groups"])


def test_report_does_not_emit_payloads_or_free_text():
    report = summarize(
        [
            json.dumps(
                {
                    "kind": "decision_receipt",
                    "schema_version": 1,
                    "decision_id": "id",
                    "content": "secret material",
                    "reason": "secret material",
                    "tool": "secret material",
                    "error_category": "secret material",
                }
            )
        ]
    )
    assert "secret material" not in json.dumps(report)


def test_runtime_reports_unknown_and_configured_tools_without_trusting_results():
    base = {
        "schema_version": 1,
        "operation": "authorize",
        "tool_name": "example_inspect",
        "params": {},
        "origins": ["external"],
        "config": {},
    }
    result = dispatch(base)["result"]
    assert result["classification_source"] == "unknown"
    assert result["reason_code"] == "unknown_tool"
    result = dispatch({**base, "config": {"toolEffects": {"example_inspect": "read"}}})["result"]
    assert result["classification_source"] == "configured_inventory"
    assert result["decision"] == "allow" and result["provenance"] == "untrusted"
    assert len(result["policy_fingerprint"]) == 64


def test_policy_fingerprint_uses_the_loaded_snapshot_without_an_extra_read(tmp_path, monkeypatch):
    import builtins
    import jataayu.api as api

    policy = tmp_path / "policy.yaml"
    policy.write_text("defaults: {forbidden_capabilities: []}\n")
    request = {
        "schema_version": 1,
        "operation": "authorize",
        "tool_name": "exec",
        "params": {},
        "origins": ["owner"],
        "config": {"policyFile": str(policy)},
    }
    expected = dispatch(request)["result"]
    reads = []
    original_open = builtins.open
    original_load = api._load_agent_policy

    def track_open(path, *args, **kwargs):
        if str(path) == str(policy):
            reads.append(path)
        return original_open(path, *args, **kwargs)

    def load_then_change(path, agent):
        loaded = original_load(path, agent)
        policy.write_text("defaults: {forbidden_capabilities: [exec]}\n")
        return loaded

    monkeypatch.setattr(builtins, "open", track_open)
    monkeypatch.setattr(api, "_load_agent_policy", load_then_change)
    result = dispatch(request)["result"]
    assert len(reads) == 1
    assert result["decision"] == "allow"
    assert result["policy_fingerprint"] == expected["policy_fingerprint"]
    monkeypatch.setattr(api, "_load_agent_policy", original_load)
    next_result = dispatch(request)["result"]
    assert next_result["decision"] == "deny"
    assert next_result["policy_fingerprint"] != result["policy_fingerprint"]


def test_policy_fingerprint_handles_directories_and_same_stat_edits(tmp_path):
    import os

    policy = tmp_path / "policy.yaml"
    policy.write_text("defaults: {mode: observe}\n")
    stat = policy.stat()
    request = {
        "schema_version": 1,
        "operation": "authorize",
        "tool_name": "exec",
        "params": {},
        "origins": ["external"],
        "config": {"policyFile": str(tmp_path)},
    }
    before = dispatch(request)["result"]
    policy.write_text("defaults: {mode: enforce}\n")
    os.utime(policy, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    after = dispatch(request)["result"]
    assert before["decision"] == "allow" and after["decision"] == "deny"
    assert before["policy_fingerprint"] != after["policy_fingerprint"]
