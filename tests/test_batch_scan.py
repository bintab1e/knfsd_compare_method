import json
from pathlib import Path

import compare_method.batch_scan as batch_scan

from compare_method.batch_scan import _input_payload, _scan_resilient, _split_sarif


def test_split_sarif_keeps_pattern_rule_results(tmp_path: Path) -> None:
    manifest_path = tmp_path / "campaigns/CAMPAIGN-TEST/patterns/PATTERN-A/round-1/manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest = {
        "campaign_id": "CAMPAIGN-TEST",
        "pattern_id": "PATTERN-A",
        "round": 1,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "rule/a"},
                            {"id": "rule/b"},
                        ]
                    }
                },
                "results": [
                    {"ruleId": "rule/a", "ruleIndex": 0, "message": {"text": "a"}},
                    {"ruleId": "rule/b", "ruleIndex": 1, "message": {"text": "b"}},
                ],
            }
        ],
    }
    records = [
        {
            "pattern_id": "PATTERN-A",
            "rule_ids": ["rule/a"],
            "round_manifest_path": manifest_path,
            "round_manifest": manifest,
        }
    ]
    counts = _split_sarif(sarif, records, tmp_path)
    assert counts == {"PATTERN-A": 1}
    output = json.loads(
        (tmp_path / "analysis/codeql/PATTERN-A/round-1.sarif").read_text(encoding="utf-8")
    )
    result = output["runs"][0]["results"][0]
    assert result["ruleId"] == "rule/a"
    assert "ruleIndex" not in result
    assert output["runs"][0]["tool"]["driver"]["rules"] == [{"id": "rule/a"}]


def test_batch_input_changes_when_query_changes(tmp_path: Path) -> None:
    database = tmp_path / "db"
    database.mkdir()
    query = tmp_path / "rule.ql"
    query.write_text("one", encoding="utf-8")
    config = {
        "version": "1.0.0",
        "bundle": {"sha256": "a" * 64},
        "scan": {"batch_size": 16},
        "database": {"expected_source_commit": "commit"},
    }
    record = {
        "pattern_id": "PATTERN-A",
        "artifact_sha256": "b" * 64,
        "semantic_review_sha256": "c" * 64,
        "rule_ids": ["rule/a"],
        "queries": [
            {
                "pattern_id": "PATTERN-A",
                "rule_id": "rule/a",
                "path": query,
                "sha256": batch_scan.sha256_file(query),
            }
        ],
    }
    first = _input_payload(tmp_path, config, database, [record])
    query.write_text("two", encoding="utf-8")
    record["queries"][0]["sha256"] = batch_scan.sha256_file(query)
    second = _input_payload(tmp_path, config, database, [record])
    assert first != second


def test_resilient_scan_quarantines_only_failing_query(monkeypatch, tmp_path: Path) -> None:
    good = tmp_path / "good.ql"
    bad = tmp_path / "bad.ql"
    good.write_text("good", encoding="utf-8")
    bad.write_text("bad", encoding="utf-8")
    queries = [
        {"pattern_id": "PATTERN-A", "rule_id": "rule/good", "path": good, "sha256": batch_scan.sha256_file(good)},
        {"pattern_id": "PATTERN-B", "rule_id": "rule/bad", "path": bad, "sha256": batch_scan.sha256_file(bad)},
    ]

    def fake_run(command, cwd, timeout_seconds=None):
        output = Path(next(value.split("=", 1)[1] for value in command if value.startswith("--output=")))
        query_names = {Path(value).name for value in command if value.endswith(".ql")}
        if "bad.ql" in query_names:
            return {"exit_code": 2, "stderr_tail": "bad query", "stdout_tail": ""}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
        return {"exit_code": 0, "stderr_tail": "", "stdout_tail": ""}

    monkeypatch.setattr(batch_scan, "_run", fake_run)
    successful, quarantined = _scan_resilient(
        tmp_path,
        tmp_path / "codeql",
        tmp_path / "db",
        1024,
        10,
        tmp_path / "batch",
        "f" * 64,
        queries,
    )
    assert [item["queries"][0]["rule_id"] for item in successful] == ["rule/good"]
    assert [item["query"]["rule_id"] for item in quarantined] == ["rule/bad"]
