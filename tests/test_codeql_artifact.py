import json
import subprocess
from pathlib import Path

import pytest

from compare_method.codeql_artifact import _run, materialize, validate_artifact


def _artifact(status: str = "preflight_passed") -> dict:
    query_path = "queries/Test.ql"
    positive = "tests/test/positive.cpp"
    negative = "tests/test/negative.cpp"
    expected = "tests/test/Test.expected"
    qlref = "tests/test/Test.qlref"
    return {
        "schema_version": "1.0.0",
        "pattern_id": "PATTERN-TEST-01",
        "pattern_ir_version": 1,
        "rule_plan_version": 1,
        "artifact_version": 1,
        "status": status,
        "pack": {
            "name": "tobabz/test-rule",
            "version": "0.1.0",
            "dependencies": {"codeql/cpp-all": "*"},
        },
        "queries": [
            {
                "path": query_path,
                "rule_id": "test/rule",
                "tier": "strict",
                "query_kind": "problem",
                "content": "import cpp\nfrom Function f select f, f.getName()",
            }
        ],
        "tests": [
            {"path": positive, "content": "void bad() {}"},
            {"path": negative, "content": "void safe() {}"},
            {"path": expected, "content": ""},
            {"path": qlref, "content": "queries/Test.ql"},
        ],
        "controls": [
            {"control_id": "positive", "expectation": "hit", "description": "bad", "test_paths": [positive, expected]},
            {"control_id": "negative", "expectation": "no_hit", "description": "safe", "test_paths": [negative, expected]},
        ],
        "review_notes": [],
    }


def test_materialize_is_idempotent(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text(json.dumps(_artifact()), encoding="utf-8")
    first, manifest = materialize(repo, artifact_path, tmp_path / "generated")
    second, _ = materialize(repo, artifact_path, tmp_path / "generated")
    assert first == second
    assert manifest["gate"]["materialized"] is True
    assert (first / "queries" / "Test.ql").is_file()


def test_materialize_refuses_path_traversal(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    artifact = _artifact()
    artifact["queries"][0]["path"] = "../escape.ql"
    with pytest.raises(Exception):
        validate_artifact(repo, artifact)


def test_proposed_requires_explicit_override(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="not preflight_passed"):
        validate_artifact(repo, _artifact("proposed"))
    validate_artifact(repo, _artifact("proposed"), allow_proposed=True)
    validate_artifact(repo, _artifact("needs_revision"), allow_proposed=True)
    with pytest.raises(ValueError, match="not preflight_passed"):
        validate_artifact(repo, _artifact("rejected"), allow_proposed=True)


def test_run_records_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=args[0], timeout=kwargs["timeout"], output="partial", stderr="slow"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _run(["codeql", "database", "analyze"], tmp_path, timeout_seconds=7)
    assert result["exit_code"] == 124
    assert result["timeout_seconds"] == 7
    assert result["timed_out"] is True
    assert result["stdout_tail"] == "partial"
    assert result["stderr_tail"] == "slow"
