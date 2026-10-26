import json
import threading
import time
from pathlib import Path

import compare_method.pipeline as pipeline

from compare_method.pipeline import _group_state, _source_is_v2_only, init_campaign, selected_case_paths


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
    ):
        (directory / name).write_text("{}", encoding="utf-8")
    state = _group_state(tmp_path, group)
    assert state["codeql"].name == "codeql-v2.json"
    assert state["codeql_version"] == 2
    assert state["reviewed_codeql"].name == "codeql-v1.reviewed.json"
    assert state["reviewed_codeql_version"] == 1


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
