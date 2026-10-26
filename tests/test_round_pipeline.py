import json
from pathlib import Path

from compare_method.round_pipeline import init_round, round_status


def test_round_manifest_binds_inputs_and_starts_empty(tmp_path: Path) -> None:
    repo = tmp_path
    pattern = repo / "pattern.json"
    plan = repo / "plan.json"
    artifact = repo / "artifact.json"
    pattern.write_text(json.dumps({"pattern_id": "PATTERN-TEST-01"}), encoding="utf-8")
    plan.write_text("{}", encoding="utf-8")
    artifact.write_text(json.dumps({"pattern_id": "PATTERN-TEST-01"}), encoding="utf-8")
    manifest_path, manifest = init_round(
        repo, "CAMPAIGN-TEST", 1, pattern, plan, artifact, []
    )
    assert manifest["round"] == 1
    status = round_status(repo, manifest_path)
    assert status["gates"]["candidate_count"] == 0
    assert status["gates"]["round_closed"] is False


def test_round_init_is_idempotent(tmp_path: Path) -> None:
    pattern = tmp_path / "pattern.json"
    plan = tmp_path / "plan.json"
    artifact = tmp_path / "artifact.json"
    pattern.write_text(json.dumps({"pattern_id": "PATTERN-TEST-01"}), encoding="utf-8")
    plan.write_text("{}", encoding="utf-8")
    artifact.write_text(json.dumps({"pattern_id": "PATTERN-TEST-01"}), encoding="utf-8")
    first = init_round(tmp_path, "CAMPAIGN-TEST", 1, pattern, plan, artifact, [])
    second = init_round(tmp_path, "CAMPAIGN-TEST", 1, pattern, plan, artifact, [])
    assert first == second
