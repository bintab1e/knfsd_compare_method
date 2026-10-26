import json
from pathlib import Path

from compare_method.runtime_dispatch import dispatch_plan


def _job(candidate: str, function: str, adapter=None) -> dict:
    value = {"candidate_id": candidate, "target_functions": [function]}
    if adapter is not None:
        value["validation_adapter"] = adapter
    return value


def test_legacy_rpc_job_is_ready(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    jobs = tmp_path / "jobs"
    path = jobs / "CANDIDATE-ONE" / "kasan.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_job("CANDIDATE-ONE", "nfsd4_decode_verify")), encoding="utf-8")
    plan = dispatch_plan(repo, "kasan", jobs)
    assert plan["counts"] == {"ready": 1, "harness_gap": 0}
    assert plan["jobs"][0]["adapter"]["kind"] == "rpc_template"


def test_unknown_job_becomes_harness_gap(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    jobs = tmp_path / "jobs"
    path = jobs / "CANDIDATE-TWO" / "kcsan.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_job("CANDIDATE-TWO", "unknown_target")), encoding="utf-8")
    plan = dispatch_plan(repo, "kcsan", jobs)
    assert plan["counts"] == {"ready": 0, "harness_gap": 1}
    assert "no supported" in plan["jobs"][0]["reason"]


def test_stage1_requires_deployment_and_safe_path(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    jobs = tmp_path / "jobs"
    path = jobs / "CANDIDATE-THREE" / "kasan.json"
    path.parent.mkdir(parents=True)
    adapter = {
        "kind": "syzkaller_stage1",
        "adapter_id": "stage1",
        "source_path": "../etc/passwd",
        "symbol": "nfsd_bad",
        "program_path": None,
        "reason": None,
    }
    path.write_text(json.dumps(_job("CANDIDATE-THREE", "nfsd_bad", adapter)), encoding="utf-8")
    plan = dispatch_plan(repo, "kasan", jobs)
    assert plan["jobs"][0]["dispatch_status"] == "harness_gap"
    assert "safe kernel-relative" in plan["jobs"][0]["reason"]
