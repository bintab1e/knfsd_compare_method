import json
from pathlib import Path

import pytest

import compare_method.campaign_driver as driver
from compare_method.common import sha256_file


def test_default_driver_never_opens_sealed_holdout(monkeypatch, tmp_path: Path) -> None:
    calls = []
    campaign = {
        "campaign_id": "CAMPAIGN-TEST",
        "split": {"public_path": "public.json"},
    }
    (tmp_path / "public.json").write_text(
        json.dumps({"sealed_holdout": {"commitment": "a" * 64}}), encoding="utf-8"
    )
    monkeypatch.setattr(driver, "_campaign", lambda repo, campaign_id: campaign)
    monkeypatch.setattr(
        driver,
        "drive_case_partition",
        lambda repo, current, partition, workers: calls.append(partition),
    )
    monkeypatch.setattr(
        driver,
        "drive_fast_patterns",
        lambda *args: {"semantically_accepted": 1},
    )
    monkeypatch.setattr(
        driver,
        "run_batch_scan",
        lambda *args, **kwargs: {
            "status": "COMPLETE",
            "batch_input_hash": "b" * 64,
            "pattern_count": 1,
            "query_count": 1,
            "quarantined_query_count": 0,
        },
    )
    monkeypatch.setattr(driver, "case_metrics", lambda *args: {})
    monkeypatch.setattr(driver, "group_metrics", lambda *args: {})
    result = driver.run_campaign(tmp_path, "CAMPAIGN-TEST", 1, 1, 1, 1)
    assert calls == ["development", "validation"]
    assert result["stage_status"]["SEALED_HOLDOUT"] == "LOCKED"
    assert result["stage_status"]["RUNTIME_VALIDATION"] == "PENDING"


def test_case_stage_rejects_sealed_holdout_before_selection(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Sealed Holdout is locked"):
        driver.pipeline.run_case_stage(
            tmp_path,
            {"campaign_id": "CAMPAIGN-TEST"},
            "extraction",
            "sealed_holdout",
            1,
            False,
        )


def test_fast_author_partial_failure_preserves_progress_and_retries(
    monkeypatch, tmp_path: Path
) -> None:
    metrics = [
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 0,
            "rule_plans": 0,
            "codeql": 0,
            "preflight_passed": 0,
            "semantically_accepted": 0,
            "needs_revision": 0,
            "rejected": 0,
        },
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 0,
            "rule_plans": 0,
            "codeql": 0,
            "preflight_passed": 0,
            "semantically_accepted": 0,
            "needs_revision": 0,
            "rejected": 0,
        },
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 1,
            "rule_plans": 0,
            "codeql": 0,
            "preflight_passed": 0,
            "semantically_accepted": 0,
            "needs_revision": 0,
            "rejected": 0,
        },
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 1,
            "rule_plans": 0,
            "codeql": 0,
            "preflight_passed": 0,
            "semantically_accepted": 0,
            "needs_revision": 0,
            "rejected": 0,
        },
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 2,
            "rule_plans": 2,
            "codeql": 2,
            "preflight_passed": 2,
            "semantically_accepted": 2,
            "needs_revision": 0,
            "rejected": 0,
        },
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 2,
            "rule_plans": 2,
            "codeql": 2,
            "preflight_passed": 2,
            "semantically_accepted": 2,
            "needs_revision": 0,
            "rejected": 0,
        },
        {
            "groups": 2,
            "patterns": 2,
            "fast_bundles": 2,
            "rule_plans": 2,
            "codeql": 2,
            "preflight_passed": 2,
            "semantically_accepted": 2,
            "needs_revision": 0,
            "rejected": 0,
        },
    ]
    calls: list[str] = []

    def fake_metrics(*args):
        if len(metrics) > 1:
            return metrics.pop(0)
        return metrics[0]

    def fake_stage(repo, campaign, stage, max_jobs, dry_run, workers=1):
        calls.append(stage)
        if stage == "codeql-fast-author" and calls.count(stage) == 1:
            raise RuntimeError("transient author failure")
        return {}

    monkeypatch.setattr(driver, "group_metrics", fake_metrics)
    monkeypatch.setattr(driver.pipeline, "run_pattern_stage", fake_stage)
    result = driver.drive_fast_patterns(tmp_path, {}, 1, 1)

    assert calls.count("codeql-fast-author") == 2
    assert result["semantically_accepted"] == 2


def test_holdout_release_is_aggregate_only_and_one_time(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas/holdout-aggregate.schema.json").write_text(
        (source_root / "schemas/holdout-aggregate.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    campaign_dir = tmp_path / "campaigns/CAMPAIGN-TEST"
    campaign_dir.mkdir(parents=True)
    public = campaign_dir / "dataset-split.public.json"
    public.write_text(
        json.dumps({"sealed_holdout": {"commitment": "a" * 64}}), encoding="utf-8"
    )
    (campaign_dir / "manifest.json").write_text(
        json.dumps(
            {
                "campaign_id": "CAMPAIGN-TEST",
                "split": {
                    "public_path": str(public.relative_to(tmp_path)),
                    "public_sha256": sha256_file(public),
                },
            }
        ),
        encoding="utf-8",
    )
    aggregate = tmp_path / "aggregate.json"
    aggregate.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "campaign_id": "CAMPAIGN-TEST",
                "milestone_id": "MILESTONE-01",
                "evaluated_at": "2026-10-27T00:00:00+00:00",
                "sealed_holdout_commitment": "a" * 64,
                "metrics": {"recall": 0.8, "detected": 8, "total": 10},
            }
        ),
        encoding="utf-8",
    )
    result = driver.release_milestone_holdout(
        tmp_path,
        "CAMPAIGN-TEST",
        "MILESTONE-01",
        aggregate,
        "RELEASE-SEALED-HOLDOUT",
    )
    assert result["case_level_results_released"] is False
    with pytest.raises(ValueError, match="already been released"):
        driver.release_milestone_holdout(
            tmp_path,
            "CAMPAIGN-TEST",
            "MILESTONE-01",
            aggregate,
            "RELEASE-SEALED-HOLDOUT",
        )
