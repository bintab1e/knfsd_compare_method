import json
import threading
import time
from pathlib import Path

import compare_method.pipeline as pipeline

from compare_method.pipeline import _group_state, _source_is_v2_only, init_campaign, selected_case_paths


def _fast_artifact(status="proposed"):
    return {
        "schema_version": "1.0.0",
        "pattern_id": "PATTERN-TEST-01",
        "pattern_ir_version": 1,
        "rule_plan_version": 1,
        "artifact_version": 1,
        "status": status,
        "pack": {
            "name": "tobabz/fast-test",
            "version": "0.1.0",
            "dependencies": {"codeql/cpp-all": "*"},
        },
        "queries": [
            {
                "path": "queries/Test.ql",
                "rule_id": "tobabz/test",
                "tier": "strict",
                "query_kind": "problem",
                "content": "/**\n * @id tobabz/test\n * @kind problem\n */\nimport cpp\nfrom Function f select f, f.getName()",
            }
        ],
        "tests": [
            {"path": "tests/test/test.cpp", "content": "void bad() {}"},
            {"path": "tests/test/Test.qlref", "content": "queries/Test.ql"},
            {"path": "tests/test/Test.expected", "content": ""},
        ],
        "controls": [
            {
                "control_id": "positive",
                "expectation": "hit",
                "description": "positive",
                "test_paths": ["tests/test/test.cpp", "tests/test/Test.expected"],
            },
            {
                "control_id": "negative",
                "expectation": "no_hit",
                "description": "negative",
                "test_paths": ["tests/test/test.cpp", "tests/test/Test.expected"],
            },
        ],
        "review_notes": [],
    }


def _fast_plan():
    return {
        "pattern_id": "PATTERN-TEST-01",
        "pattern_ir_version": 1,
        "rule_plan_version": 1,
        "codeql_support": "direct",
        "sources": ["decoded count"],
        "sinks": ["copy"],
        "flow_steps": [],
        "required_guards": ["finite bound"],
        "barriers": [],
        "scope_constraints": ["remote KNFSd"],
        "rule_variants": [
            {
                "rule_id": "tobabz/test",
                "tier": "strict",
                "protocol_scope": ["nfs3"],
                "processing_stage": ["decode"],
            }
        ],
    }


def test_v2_only_filter_is_narrow() -> None:
    base = {"facts": {"protocol_versions_raw": ["NFSv2"]}}
    assert _source_is_v2_only(base)
    assert not _source_is_v2_only({"facts": {"protocol_versions_raw": ["NFSv2 / NFSv3"]}})
    assert not _source_is_v2_only({"facts": {"protocol_versions_raw": ["RPC/XDR"]}})


def test_init_is_idempotent_on_repository_fixture(tmp_path: Path) -> None:
    repo = tmp_path
    for directory in ("config", "data/cases", "schemas"):
        (repo / directory).mkdir(parents=True, exist_ok=True)
    source_root = Path(__file__).resolve().parents[1]
    for name in ("dataset-split.yaml", "llm.yaml"):
        (repo / "config" / name).write_text((source_root / "config" / name).read_text(encoding="utf-8"), encoding="utf-8")
    (repo / "schemas" / "campaign.schema.json").write_text(
        (source_root / "schemas" / "campaign.schema.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    case = {
        "case_id": "CASE-KNFSD-CVE-2099-9999-RC01",
        "case_group_id": "GROUP-KNFSD-CVE-2099-9999",
        "source_implementation": "KNFSD",
        "identifier": {"cve_id": "CVE-2099-9999"},
        "facts": {
            "protocol_versions_raw": ["NFSv4"],
            "root_cause_claims": ["race"],
            "published_or_commit_dates": ["2099-01-01"],
        },
    }
    (repo / "data/cases/case.json").write_text(json.dumps(case), encoding="utf-8")
    first = init_campaign(repo, "CAMPAIGN-TEST")
    second = init_campaign(repo, "CAMPAIGN-TEST")
    assert first == second
    paths, excluded = selected_case_paths(repo, first, "development")
    assert excluded == 0
    assert len(paths) in {0, 1}


def test_group_state_selects_latest_codeql_revision(tmp_path: Path) -> None:
    group = tmp_path / "GROUP-TEST.json"
    group.write_text(json.dumps({"members": []}), encoding="utf-8")
    directory = tmp_path / "patterns/groups/GROUP-TEST"
    directory.mkdir(parents=True)
    for name in (
        "codeql-v1.json",
        "codeql-v1.reviewed.json",
        "codeql-v2.json",
        "codeql-v2.json.audit.json",
        "semantic-review-v1.json",
    ):
        (directory / name).write_text("{}", encoding="utf-8")
    state = _group_state(tmp_path, group)
    assert state["codeql"].name == "codeql-v2.json"
    assert state["codeql_version"] == 2
    assert state["reviewed_codeql"].name == "codeql-v1.reviewed.json"
    assert state["reviewed_codeql_version"] == 1
    assert state["semantic_review"].name == "semantic-review-v1.json"
    assert state["semantic_review_version"] == 1


def test_role_batch_respects_worker_bound(monkeypatch, tmp_path: Path) -> None:
    lock = threading.Lock()
    active = 0
    max_active = 0

    def fake_run_role(role, repo, inputs, output, dry_run, split_manifest):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return True

    monkeypatch.setattr(pipeline, "_run_role", fake_run_role)
    jobs = [("extractor", [], tmp_path / f"v{index}.json") for index in range(6)]
    completed = pipeline._run_role_batch(jobs, tmp_path, False, None, workers=2)

    assert completed == 6
    assert max_active == 2


def test_fast_bundle_derives_plan_and_artifact(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    (tmp_path / "schemas").mkdir()
    for name in ("rule-plan.schema.json", "codeql-artifact.schema.json"):
        (tmp_path / "schemas" / name).write_text(
            (source_root / "schemas" / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    directory = tmp_path / "patterns/groups/GROUP-TEST"
    directory.mkdir(parents=True)
    pattern = directory / "v1.json"
    pattern.write_text(json.dumps({"pattern_id": "PATTERN-TEST-01"}), encoding="utf-8")
    bundle = directory / "fast-bundle-v1.json"
    bundle.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "rule_plan": _fast_plan(),
                "codeql_artifact": _fast_artifact(),
            }
        ),
        encoding="utf-8",
    )
    state = {
        "directory": directory,
        "pattern": pattern,
        "reviewed_pattern": directory / "v1.reviewed.json",
        "rule_plan": directory / "rule-plan-v1.json",
        "fast_bundle": bundle,
    }
    pipeline._derive_fast_bundle(tmp_path, state)
    assert json.loads(state["rule_plan"].read_text(encoding="utf-8"))["codeql_support"] == "direct"
    assert json.loads((directory / "codeql-v1.json").read_text(encoding="utf-8"))["status"] == "proposed"


def test_fast_gate_only_marks_preflight_passed(monkeypatch, tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas/codeql-artifact.schema.json").write_text(
        (source_root / "schemas/codeql-artifact.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    directory = tmp_path / "patterns/groups/GROUP-TEST"
    directory.mkdir(parents=True)
    artifact_path = directory / "codeql-v1.json"
    artifact_path.write_text(json.dumps(_fast_artifact()), encoding="utf-8")
    verification = tmp_path / "preflight.json"
    verification.write_text(
        json.dumps({"gate": {"compiled": True, "qltests_passed": True}}), encoding="utf-8"
    )
    monkeypatch.setattr(pipeline, "_codeql_preflight", lambda repo, artifact: verification)
    state = {"directory": directory, "codeql": artifact_path, "codeql_version": 1}
    assert pipeline._fast_gate_artifact(tmp_path, state, False) == "preflight_passed"
    reviewed = json.loads((directory / "codeql-v1.reviewed.json").read_text(encoding="utf-8"))
    assert reviewed["status"] == "preflight_passed"


def test_semantic_acceptance_requires_all_independent_checks(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas/semantic-review.schema.json").write_text(
        (source_root / "schemas/semantic-review.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    directory = tmp_path / "patterns/groups/GROUP-TEST"
    directory.mkdir(parents=True)
    gate = directory / "codeql-v1.reviewed.json"
    artifact = _fast_artifact("preflight_passed")
    gate.write_text(json.dumps(artifact), encoding="utf-8")
    review = directory / "semantic-review-v1.json"
    review.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "pattern_id": artifact["pattern_id"],
                "artifact_version": 1,
                "artifact_sha256": pipeline.sha256_file(gate),
                "status": "semantically_accepted",
                "risk_tier": "standard",
                "remote_scope_verified": True,
                "invariant_implemented": True,
                "guards_verified": False,
                "realistic_tests": True,
                "findings": [],
                "review_notes": [],
            }
        ),
        encoding="utf-8",
    )
    state = {
        "reviewed_codeql": gate,
        "reviewed_codeql_version": 1,
        "codeql_version": 1,
    }
    import pytest

    with pytest.raises(ValueError, match="every semantic check"):
        pipeline._validate_semantic_review(tmp_path, state, review)
