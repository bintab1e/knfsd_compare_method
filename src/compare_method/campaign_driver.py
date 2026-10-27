from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import pipeline
from .batch_scan import run_batch_scan
from .common import repo_root


TERMINAL_EXTRACTION = {"accepted", "insufficient_evidence", "rejected"}


def emit(event: str, **details: object) -> None:
    print(
        json.dumps(
            {
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "event": event,
                **details,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _campaign(repo: Path, campaign_id: str) -> dict[str, Any]:
    return _load(pipeline._campaign_dir(repo, campaign_id) / "manifest.json")


def case_metrics(repo: Path, campaign: dict[str, Any], partition: str) -> dict[str, int]:
    paths, excluded = pipeline.selected_case_paths(repo, campaign, partition)
    states = [pipeline._case_state(repo, path) for path in paths]
    reviewed = [
        _load(state["reviewed_extraction"])
        for state in states
        if state["reviewed_extraction"] is not None
    ]
    return {
        "selected": len(paths),
        "excluded_v2_only": excluded,
        "extracted": sum(state["extraction"] is not None for state in states),
        "reviewed": len(reviewed),
        "terminal_extraction": sum(item.get("status") in TERMINAL_EXTRACTION for item in reviewed),
        "accepted_extraction": sum(item.get("status") == "accepted" for item in reviewed),
        "mapped": sum(state["mapping"] is not None for state in states),
        "context": sum(state["context"] is not None for state in states),
        "mapping_reviewed": sum(state["reviewed_mapping"] is not None for state in states),
        "active_mapping": sum(pipeline._active_mapping(state["reviewed_mapping"]) for state in states),
    }


def group_metrics(repo: Path, campaign: dict[str, Any]) -> dict[str, int]:
    states = [
        pipeline._group_state(repo, path)
        for path in pipeline.build_pattern_groups(repo, campaign)
    ]
    accepted = needs_revision = rejected = materialized = 0
    for state in states:
        reviewed = state["reviewed_codeql"]
        if reviewed is None:
            continue
        artifact = _load(reviewed)
        status = artifact["status"]
        accepted += status == "accepted"
        needs_revision += status == "needs_revision"
        rejected += status == "rejected"
        verification = (
            repo
            / "codeql"
            / "generated"
            / artifact["pattern_id"]
            / f"v{artifact['artifact_version']}"
            / "verification.json"
        )
        if verification.is_file():
            gate = _load(verification).get("gate", {})
            materialized += gate.get("compiled") is True and gate.get("qltests_passed") is True
    return {
        "groups": len(states),
        "patterns": sum(state["pattern"].is_file() for state in states),
        "fast_bundles": sum(state["fast_bundle"].is_file() for state in states),
        "rule_plans": sum(state["rule_plan"].is_file() for state in states),
        "codeql": sum(state["codeql"] is not None for state in states),
        "accepted": accepted,
        "needs_revision": needs_revision,
        "rejected": rejected,
        "materialized": materialized,
    }


def drive_case_partition(
    repo: Path,
    campaign: dict[str, Any],
    partition: str,
    workers: int,
) -> None:
    emit("partition_started", partition=partition, metrics=case_metrics(repo, campaign, partition))
    initial = case_metrics(repo, campaign, partition)
    downstream_complete = (
        initial["mapped"] >= initial["accepted_extraction"]
        and initial["context"] >= initial["accepted_extraction"]
        and initial["mapping_reviewed"] >= initial["accepted_extraction"]
    )
    if not downstream_complete:
        for cycle in range(1, 9):
            before = case_metrics(repo, campaign, partition)
            if before["terminal_extraction"] >= before["selected"]:
                break
            pipeline.run_case_stage(
                repo,
                campaign,
                "extraction-review",
                partition,
                before["selected"],
                False,
                workers=workers,
            )
            reviewed = case_metrics(repo, campaign, partition)
            if reviewed["terminal_extraction"] >= reviewed["selected"]:
                break
            pipeline.run_case_stage(
                repo,
                campaign,
                "extraction",
                partition,
                reviewed["selected"],
                False,
                workers=workers,
            )
            after = case_metrics(repo, campaign, partition)
            emit("extraction_cycle", partition=partition, cycle=cycle, before=before, after=after)
            if after["extracted"] == before["extracted"] and after["reviewed"] == before["reviewed"]:
                break
    else:
        emit(
            "extraction_rework_skipped",
            partition=partition,
            reason="all accepted extractions already have downstream mapping artifacts",
            metrics=initial,
        )
    for stage, metric, target_metric, stage_workers in (
        ("mapping", "mapped", "accepted_extraction", workers),
        ("context", "context", "mapped", 1),
        ("mapping-review", "mapping_reviewed", "mapped", workers),
    ):
        before = case_metrics(repo, campaign, partition)
        if before[metric] < before[target_metric]:
            pipeline.run_case_stage(
                repo,
                campaign,
                stage,
                partition,
                before["selected"],
                False,
                workers=stage_workers,
            )
    emit("partition_finished", partition=partition, metrics=case_metrics(repo, campaign, partition))


def drive_fast_patterns(
    repo: Path,
    campaign: dict[str, Any],
    pattern_workers: int,
    max_repair_rounds: int,
) -> dict[str, int]:
    metrics = group_metrics(repo, campaign)
    emit("fast_pattern_pipeline_started", metrics=metrics)
    if metrics["patterns"] < metrics["groups"]:
        pipeline.run_pattern_stage(
            repo, campaign, "pattern", metrics["groups"], False, workers=pattern_workers
        )
    author_batch_size = pattern_workers * 4
    maximum_batches = (metrics["groups"] + author_batch_size - 1) // author_batch_size + 2
    for batch_number in range(1, maximum_batches + 1):
        before = group_metrics(repo, campaign)
        if before["codeql"] >= before["groups"]:
            break
        pipeline.run_pattern_stage(
            repo,
            campaign,
            "codeql-fast-author",
            author_batch_size,
            False,
            workers=pattern_workers,
        )
        pipeline.run_pattern_stage(
            repo, campaign, "codeql-fast-gate", before["groups"], False, workers=1
        )
        after = group_metrics(repo, campaign)
        emit(
            "fast_author_batch_finished",
            batch_number=batch_number,
            batch_size=author_batch_size,
            before=before,
            after=after,
        )
        if (
            after["fast_bundles"] == before["fast_bundles"]
            and after["codeql"] == before["codeql"]
        ):
            break
    for repair_round in range(1, max_repair_rounds + 1):
        before = group_metrics(repo, campaign)
        if before["needs_revision"] == 0:
            break
        emit("conditional_repair_started", repair_round=repair_round, metrics=before)
        pipeline.run_pattern_stage(
            repo, campaign, "codeql-author", before["groups"], False, workers=pattern_workers
        )
        pipeline.run_pattern_stage(
            repo, campaign, "codeql-fast-gate", before["groups"], False, workers=1
        )
        after = group_metrics(repo, campaign)
        emit("conditional_repair_finished", repair_round=repair_round, metrics=after)
        if after == before:
            break
    metrics = group_metrics(repo, campaign)
    emit(
        "fast_pattern_pipeline_finished",
        metrics=metrics,
        quarantined_after_fast_gate=metrics["needs_revision"] + metrics["rejected"],
    )
    return metrics


def run_campaign(
    repo: Path,
    campaign_id: str,
    workers: int,
    pattern_workers: int,
    max_repair_rounds: int,
    round_number: int,
) -> dict[str, Any]:
    if not 1 <= workers <= 8:
        raise ValueError("workers must be between 1 and 8")
    if not 1 <= pattern_workers <= workers:
        raise ValueError("pattern-workers must be between 1 and workers")
    campaign = _campaign(repo, campaign_id)
    drive_case_partition(repo, campaign, "development", workers)
    pattern_metrics = drive_fast_patterns(repo, campaign, pattern_workers, max_repair_rounds)
    if pattern_metrics["materialized"] == 0:
        raise RuntimeError("no rules passed deterministic compile/qltest gates")
    batch = run_batch_scan(repo, campaign_id, round_number, normalize=True)
    emit(
        "batch_scan_finished",
        pattern_count=batch["pattern_count"],
        query_count=batch["query_count"],
    )
    drive_case_partition(repo, campaign, "validation", workers)
    drive_case_partition(repo, campaign, "sealed_holdout", workers)
    completion = {
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campaign_id": campaign_id,
        "development": case_metrics(repo, campaign, "development"),
        "patterns": group_metrics(repo, campaign),
        "batch_scan": {
            "round": round_number,
            "pattern_count": batch["pattern_count"],
            "query_count": batch["query_count"],
        },
        "validation": case_metrics(repo, campaign, "validation"),
        "sealed_holdout": case_metrics(repo, campaign, "sealed_holdout"),
        "holdout_feedback_used": False,
    }
    emit("campaign_driver_finished", completion=completion)
    return completion


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the fast-feedback KNFSd campaign driver.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--pattern-workers", type=int, default=4)
    parser.add_argument("--max-repair-rounds", type=int, default=3)
    parser.add_argument("--round", type=int, default=1)
    args = parser.parse_args()
    result = run_campaign(
        args.repo.resolve(),
        args.campaign_id,
        args.workers,
        args.pattern_workers,
        args.max_repair_rounds,
        args.round,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
