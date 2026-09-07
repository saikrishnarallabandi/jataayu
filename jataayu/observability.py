"""Offline aggregates over metadata-only native adapter receipts.

No payloads, free-text reasons or tokens are included in this report. Legacy
alert-only ledgers are counted separately, never mixed into new denominators.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re


SAFE_TOKEN = re.compile(r"[a-zA-Z0-9_.:/-]{1,100}\Z")


def label(value):
    return value if isinstance(value, str) and SAFE_TOKEN.fullmatch(value) else "missing_or_invalid"


def summarize(lines):
    groups = {}
    excluded = Counter()
    seen = set()
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            excluded["malformed_json"] += 1
            continue
        if not isinstance(row, dict) or row.get("kind") != "decision_receipt":
            excluded["legacy_or_unrelated"] += 1
            continue
        if row.get("schema_version") != 1:
            excluded["unsupported_schema"] += 1
            continue
        decision_id = row.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            excluded["missing_decision_id"] += 1
            continue
        if decision_id in seen:
            excluded["duplicate_receipt_id"] += 1
            continue
        seen.add(decision_id)
        dimensions = {
            k: label(row.get(k))
            for k in (
                "host",
                "traffic",
                "core_fingerprint",
                "adapter_fingerprint",
                "policy_id",
                "policy_fingerprint",
                "mode",
            )
        }
        key = tuple(dimensions.values())
        if key not in groups:
            groups[key] = {
                "dimensions": dimensions,
                "events": 0,
                "hooks": Counter(),
                "tools": Counter(),
                "verdicts": Counter(),
                "dispositions": Counter(),
                "provenance_reasons": Counter(),
                "screening_states": Counter(),
                "errors": Counter(),
                "unknown_tool_events": 0,
                "incomplete_correlation": 0,
                "would_intervene": 0,
                "completed_after_persist": 0,
                "durations_ms": [],
            }
        g = groups[key]
        g["events"] += 1
        for target, source in (
            ("hooks", "hook"),
            ("tools", "tool"),
            ("verdicts", "verdict"),
            ("dispositions", "adapter_disposition"),
            ("provenance_reasons", "provenance_reason"),
            ("screening_states", "screening_state"),
            ("errors", "error_category"),
        ):
            if row.get(source) is not None:
                g[target][label(row[source])] += 1
        g["unknown_tool_events"] += row.get("classification_source") == "unknown"
        g["incomplete_correlation"] += row.get("correlation_status") != "available"
        g["would_intervene"] += row.get("would_intervene") is True
        g["completed_after_persist"] += row.get("completed_after_persist") is True
        duration = row.get("duration_ms")
        if type(duration) in (int, float) and 0 <= duration < 86400000:
            g["durations_ms"].append(duration)
    for g in groups.values():
        durations = sorted(g.pop("durations_ms"))
        g["latency_ms"] = {
            "samples": len(durations),
            "p50": durations[(len(durations) - 1) // 2] if durations else None,
            "p95": durations[int((len(durations) - 1) * 0.95)] if durations else None,
        }
    return {
        "schema_version": 1,
        "groups": list(groups.values()),
        "excluded": dict(excluded),
        "interpretation": "Event counts, not unique actions or ground-truth accuracy. "
        "Adapter dispositions are not host acknowledgements.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    with args.log.open() as file:
        print(json.dumps(summarize(file), indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
