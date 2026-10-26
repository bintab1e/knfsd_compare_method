from __future__ import annotations

import json
from pathlib import Path

from compare_method.candidate import normalize_sarif


def test_normalize_sarif_is_deterministic_and_deduplicates(tmp_path: Path) -> None:
    result = {
        "ruleId": "example/rule",
        "level": "warning",
        "message": {"text": "decoded count reaches allocation"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "fs/nfsd/nfs4xdr.c"},
                    "region": {"startLine": 42, "startColumn": 3},
                }
            }
        ],
    }
    sarif = {"version": "2.1.0", "runs": [{"results": [result, result]}]}
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")

    first = tmp_path / "first"
    second = tmp_path / "second"
    first_paths = normalize_sarif(
        sarif_path, "CAMPAIGN-ROUND-1", "PATTERN-1", first
    )
    second_paths = normalize_sarif(
        sarif_path, "CAMPAIGN-ROUND-1", "PATTERN-1", second
    )

    assert len(first_paths) == 1
    assert first_paths[0].name == second_paths[0].name
    candidate = json.loads(first_paths[0].read_text(encoding="utf-8"))
    assert candidate["candidate_id"].startswith("CANDIDATE-")
    assert candidate["fingerprint"].startswith("sha256:")
    assert len(candidate["detections"]) == 2
    assert candidate["detections"][0]["location"]["path"] == "fs/nfsd/nfs4xdr.c"
