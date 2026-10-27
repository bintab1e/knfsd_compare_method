from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from . import pipeline
from .batch_scan import run_batch_scan
from .common import repo_root, sha256_file, write_json
from .dataset_split import case_ids_in_value


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
    preflight_passed = semantically_accepted = needs_revision = rejected = 0
    for state in states:
        reviewed = state["reviewed_codeql"]
        if reviewed is None:
            continue
        artifact = _load(reviewed)
        status = artifact["status"]
        preflight_passed += status == "preflight_passed"
        needs_revision += status == "needs_revision"
        rejected += status == "rejected"
        semantic_path = state["semantic_review"]
        if semantic_path and state["semantic_review_version"] == state["codeql_version"]:
            semantic = pipeline._validate_semantic_review(repo, state, semantic_path)
            semantically_accepted += semantic["status"] == "semantically_accepted"
            needs_revision += semantic["status"] == "needs_revision"
            rejected += semantic["status"] == "rejected"
    return {
        "groups": len(states),
        "patterns": sum(state["pattern"].is_file() for state in states),
        "fast_bundles": sum(state["fast_bundle"].is_file() for state in states),
        "rule_plans": sum(state["rule_plan"].is_file() for state in states),
        "codeql": sum(state["codeql"] is not None for state in states),
        "preflight_passed": preflight_passed,
        "semantically_accepted": semantically_accepted,
        "needs_revision": needs_revision,
        "rejected": rejected,
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
        pipeline.run_pattern_stage(
            repo,
            campaign,
            "codeql-review",
            before["groups"],
            False,
            workers=pattern_workers,
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
    current = group_metrics(repo, campaign)
    pipeline.run_pattern_stage(
        repo, campaign, "codeql-fast-gate", current["groups"], False, workers=1
    )
    pipeline.run_pattern_stage(
        repo,
        campaign,
        "codeql-review",
        current["groups"],
        False,
        workers=pattern_workers,
    )
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
        pipeline.run_pattern_stage(
            repo,
            campaign,
            "codeql-review",
            before["groups"],
            False,
            workers=pattern_workers,
        )
        after = group_metrics(repo, campaign)
        emit("conditional_repair_finished", repair_round=repair_round, metrics=after)
        if after == before:
            break
    metrics = group_metrics(repo, campaign)
    emit(
        "fast_pattern_pipeline_finished",
        metrics=metrics,
        quarantined_after_review=metrics["needs_revision"] + metrics["rejected"],
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
    if pattern_metrics["semantically_accepted"] == 0:
        raise RuntimeError("no rules passed independent semantic review")
    batch = run_batch_scan(repo, campaign_id, round_number, normalize=True)
    emit(
        "batch_scan_finished",
        pattern_count=batch["pattern_count"],
        query_count=batch["query_count"],
        quarantined_query_count=batch["quarantined_query_count"],
    )
    drive_case_partition(repo, campaign, "validation", workers)
    completion = {
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campaign_id": campaign_id,
        "pipeline_state": (
            "STATIC_SCAN_COMPLETE_WITH_QUARANTINE"
            if batch["status"] == "PARTIAL"
            else "STATIC_SCAN_COMPLETE"
        ),
        "stage_status": {
            "RULE_BUILD": "COMPLETE",
            "STATIC_SCAN": "PARTIAL" if batch["status"] == "PARTIAL" else "COMPLETE",
            "VALIDATION_DATA_PREPARATION": "COMPLETE",
            "SEALED_HOLDOUT": "LOCKED",
            "RUNTIME_VALIDATION": "PENDING",
            "ADJUDICATION": "PENDING",
            "PROMOTION": "PENDING",
        },
        "development": case_metrics(repo, campaign, "development"),
        "patterns": group_metrics(repo, campaign),
        "batch_scan": {
            "round": round_number,
            "status": batch["status"],
            "batch_input_hash": batch["batch_input_hash"],
            "pattern_count": batch["pattern_count"],
            "query_count": batch["query_count"],
            "quarantined_query_count": batch["quarantined_query_count"],
        },
        "validation": case_metrics(repo, campaign, "validation"),
        "sealed_holdout": {
            "status": "LOCKED",
            "commitment": _load(repo / campaign["split"]["public_path"])["sealed_holdout"]["commitment"],
        },
    }
    emit("static_preparation_finished", completion=completion)
    return completion


def release_milestone_holdout(
    repo: Path,
    campaign_id: str,
    milestone_id: str,
    aggregate_path: Path,
    confirmation: str,
) -> dict[str, Any]:
    """Release one aggregate-only holdout result without exposing case details."""
    if confirmation != "RELEASE-SEALED-HOLDOUT":
        raise ValueError("exact --confirm RELEASE-SEALED-HOLDOUT is required")
    if not re.fullmatch(r"MILESTONE-[A-Z0-9-]+", milestone_id):
        raise ValueError("milestone ID must match MILESTONE-[A-Z0-9-]+")
    campaign = _campaign(repo, campaign_id)
    aggregate = _load(aggregate_path)
    schema = _load(repo / "schemas" / "holdout-aggregate.schema.json")
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        aggregate
    )
    if aggregate["campaign_id"] != campaign_id or aggregate["milestone_id"] != milestone_id:
        raise ValueError("holdout aggregate campaign or milestone binding differs")
    if case_ids_in_value(aggregate):
        raise ValueError("holdout aggregate must not contain case-level identifiers")
    public_path = repo / campaign["split"]["public_path"]
    if sha256_file(public_path) != campaign["split"]["public_sha256"]:
        raise ValueError("public split manifest hash changed after campaign initialization")
    commitment = _load(public_path)["sealed_holdout"]["commitment"]
    if aggregate["sealed_holdout_commitment"] != commitment:
        raise ValueError("holdout aggregate commitment does not match the sealed split")
    ledger_path = pipeline._campaign_dir(repo, campaign_id) / "control" / "holdout-release.json"
    if ledger_path.exists():
        raise ValueError("Sealed Holdout aggregate has already been released for this campaign")
    output = (
        pipeline._campaign_dir(repo, campaign_id)
        / "milestones"
        / milestone_id
        / "sealed-holdout.aggregate.json"
    )
    write_json(output, aggregate)
    ledger = {
        "schema_version": "1.0.0",
        "campaign_id": campaign_id,
        "milestone_id": milestone_id,
        "released_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "aggregate_path": str(output),
        "aggregate_sha256": sha256_file(output),
        "sealed_holdout_commitment": commitment,
        "case_level_results_released": False,
    }
    write_json(ledger_path, ledger)
    emit("sealed_holdout_aggregate_released", release=ledger)
    return ledger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare KNFSd rules and static scan results; runtime validation remains separate."
    )
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--pattern-workers", type=int, default=4)
    parser.add_argument("--max-repair-rounds", type=int, default=3)
    parser.add_argument("--round", type=int, default=1)
    parser.add_argument("--milestone-holdout", action="store_true")
    parser.add_argument("--holdout-aggregate", type=Path)
    parser.add_argument("--milestone-id")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    repo = args.repo.resolve()
    if args.milestone_holdout:
        if not args.holdout_aggregate or not args.milestone_id:
            parser.error("--milestone-holdout requires --holdout-aggregate and --milestone-id")
        result = release_milestone_holdout(
            repo,
            args.campaign_id,
            args.milestone_id,
            args.holdout_aggregate.resolve(),
            args.confirm or "",
        )
    else:
        if args.holdout_aggregate or args.milestone_id or args.confirm:
            parser.error("holdout arguments require --milestone-holdout")
        result = run_campaign(
            repo,
            args.campaign_id,
            args.workers,
            args.pattern_workers,
            args.max_repair_rounds,
            args.round,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
