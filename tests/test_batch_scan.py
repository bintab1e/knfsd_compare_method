import json
from pathlib import Path

from compare_method.batch_scan import _split_sarif


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
