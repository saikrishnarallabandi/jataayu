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
