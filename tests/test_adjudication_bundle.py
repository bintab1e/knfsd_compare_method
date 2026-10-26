import json
from pathlib import Path

from compare_method.adjudication_bundle import build_bundles


def test_builds_candidate_bundle_with_source_and_missing_runtime(tmp_path: Path) -> None:
    candidates = tmp_path / "candidates"
    source = tmp_path / "source"
    candidates.mkdir()
    source.mkdir()
    (source / "sample.c").write_text("one\ntwo\nthree\n", encoding="utf-8")
    candidate = {
        "candidate_id": "CANDIDATE-TEST",
        "detections": [{"location": {"path": "sample.c", "start_line": 2}}],
    }
    (candidates / "CANDIDATE-TEST.json").write_text(json.dumps(candidate), encoding="utf-8")
    pattern = tmp_path / "pattern.json"
    plan = tmp_path / "plan.json"
    pattern.write_text("{}", encoding="utf-8")
    plan.write_text("{}", encoding="utf-8")

    paths = build_bundles(
        candidates, pattern, plan, source, tmp_path / "runs", tmp_path / "bundles"
    )

    bundle = json.loads(paths[0].read_text(encoding="utf-8"))
    assert bundle["source_context"][0]["candidate_line"] == 2
    assert "     2\ttwo" in bundle["source_context"][0]["text"]
    assert bundle["runtime_evidence"]["kasan"]["status"] == "not_run"
