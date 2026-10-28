from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import yaml

from .candidate import normalize_sarif
from .codeql_artifact import _run
from .common import canonical_json, repo_root, sha256_bytes, sha256_file, write_json
from .pipeline import (
    _campaign_dir,
    _group_state,
    _json,
    _pattern_input,
    _validate_semantic_review,
    build_pattern_groups,
    semantic_scan_admission,
)
from .round_pipeline import _paths, init_round


def _scan_eligible_records(repo: Path, campaign_id: str, round_number: int) -> list[dict[str, Any]]:
    """Return preflight-passing rules admitted for exploratory static scan."""
    campaign = _json(_campaign_dir(repo, campaign_id) / "manifest.json")
    records: list[dict[str, Any]] = []
    seen_rule_ids: dict[str, str] = {}
    for group_path in build_pattern_groups(repo, campaign):
        state = _group_state(repo, group_path)
        artifact_path = state["reviewed_codeql"]
        semantic_path = state["semantic_review"]
        proposed_path = state["codeql"]
        pattern_path = _pattern_input(state)
        current = state["codeql_version"]
        if (
            artifact_path is None
            or semantic_path is None
            or proposed_path is None
            or pattern_path is None
            or not state["rule_plan"].is_file()
            or state["reviewed_codeql_version"] != current
            or state["semantic_review_version"] != current
        ):
            continue
        artifact = _json(artifact_path)
        semantic = _validate_semantic_review(repo, state, semantic_path)
        if artifact["status"] != "preflight_passed":
            continue
        scan_admission = semantic_scan_admission(semantic)
        if scan_admission is None:
            continue
        pack_dir = (
            repo
            / "analysis"
            / "codeql-preflight"
            / sha256_file(proposed_path)
            / artifact["pattern_id"]
            / f"v{artifact['artifact_version']}"
        )
        verification = pack_dir / "verification.json"
        if not verification.is_file():
            continue
        gate = _json(verification).get("gate", {})
        if gate.get("compiled") is not True or gate.get("qltests_passed") is not True:
            continue
        rule_ids = []
        queries = []
        for query in artifact["queries"]:
            rule_id = query["rule_id"]
            owner = seen_rule_ids.setdefault(rule_id, artifact["pattern_id"])
            if owner != artifact["pattern_id"]:
                raise ValueError(
                    f"duplicate CodeQL rule ID {rule_id} belongs to both {owner} and {artifact['pattern_id']}"
                )
            rule_ids.append(rule_id)
            query_path = pack_dir / query["path"]
            if not query_path.is_file():
                raise FileNotFoundError(f"preflight query is missing: {query_path}")
            queries.append(
                {
                    "pattern_id": artifact["pattern_id"],
                    "rule_id": rule_id,
                    "path": query_path,
                    "sha256": sha256_file(query_path),
                }
            )
        contexts = [
            repo / item["context_path"]
            for item in state["group"]["members"]
            if item["context_path"]
        ]
        manifest_path, manifest = init_round(
            repo,
            campaign_id,
            round_number,
            pattern_path,
            state["rule_plan"],
            artifact_path,
            contexts,
            semantic_path,
        )
        records.append(
            {
                "pattern_id": artifact["pattern_id"],
                "artifact_path": artifact_path,
                "artifact_sha256": sha256_file(artifact_path),
                "semantic_review_path": semantic_path,
                "semantic_review_sha256": sha256_file(semantic_path),
                "semantic_status": semantic["status"],
                "scan_admission": scan_admission,
                "pack_dir": pack_dir,
                "queries": queries,
                "rule_ids": sorted(set(rule_ids)),
                "round_manifest_path": manifest_path,
                "round_manifest": manifest,
            }
        )
    return records


def _relative(repo: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except ValueError:
        return str(path.resolve())


def _query_binding(repo: Path, query: dict[str, Any]) -> dict[str, str]:
    return {
        "pattern_id": query["pattern_id"],
        "rule_id": query["rule_id"],
        "path": _relative(repo, query["path"]),
        "sha256": query["sha256"],
    }


def _input_payload(
    repo: Path,
    config: dict[str, Any],
    database: Path,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    metadata = database / "codeql-database.yml"
    return {
        "database": _relative(repo, database),
        "database_expected_source_commit": config["database"]["expected_source_commit"],
        "database_metadata_sha256": sha256_file(metadata) if metadata.is_file() else None,
        "codeql_version": config["version"],
        "codeql_bundle_sha256": config["bundle"]["sha256"],
        "scan_config_sha256": sha256_bytes(canonical_json(config.get("scan", {}))),
        "queries": sorted(
            (
                _query_binding(repo, query)
                for record in records
                for query in record["queries"]
            ),
            key=lambda item: (item["rule_id"], item["path"]),
        ),
        "artifacts": sorted(
            [
                {
                    "pattern_id": record["pattern_id"],
                    "artifact_sha256": record["artifact_sha256"],
                    "semantic_review_sha256": record["semantic_review_sha256"],
                    "semantic_status": record["semantic_status"],
                    "scan_admission": record["scan_admission"],
                    "rule_ids": record["rule_ids"],
                }
                for record in records
            ],
            key=lambda item: item["pattern_id"],
        ),
    }


def _chunk_input(
    repo: Path, batch_input_hash: str, queries: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "batch_input_hash": batch_input_hash,
        "queries": sorted(
            (_query_binding(repo, query) for query in queries),
            key=lambda item: (item["rule_id"], item["path"]),
        ),
    }


def _scan_chunk(
    repo: Path,
    executable: Path,
    database: Path,
    ram_mb: int,
    timeout_seconds: int,
    batch_root: Path,
    batch_input_hash: str,
    queries: list[dict[str, Any]],
) -> dict[str, Any]:
    binding = _chunk_input(repo, batch_input_hash, queries)
    digest = sha256_bytes(canonical_json(binding))
    directory = batch_root / "chunks" / digest
    manifest_path = directory / "manifest.json"
    sarif_path = directory / "results.sarif"
    if manifest_path.is_file():
        manifest = _json(manifest_path)
        if manifest.get("input") != binding:
            raise ValueError(f"chunk cache input binding differs: {manifest_path}")
        if manifest.get("status") == "succeeded":
            if (
                not sarif_path.is_file()
                or manifest.get("sarif_sha256") != sha256_file(sarif_path)
            ):
                raise ValueError(f"chunk cache SARIF binding differs: {manifest_path}")
            return {
                "status": "succeeded",
                "sarif": sarif_path,
                "manifest": manifest_path,
                "cached": True,
            }
        if manifest.get("status") == "failed":
            # Failed scans can be transient (timeout, memory pressure, or an
            # interrupted host). Only successful chunks are reusable cache.
            pass
        elif manifest.get("status") != "succeeded":
            raise ValueError(f"unknown chunk cache status: {manifest_path}")

    directory.mkdir(parents=True, exist_ok=True)
    scan = _run(
        [
            str(executable),
            "database",
            "analyze",
            f"--ram={ram_mb}",
            str(database),
            *[str(query["path"]) for query in queries],
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--rerun",
        ],
        repo,
        timeout_seconds=timeout_seconds,
    )
    succeeded = scan["exit_code"] == 0 and sarif_path.is_file()
    manifest = {
        "schema_version": "1.0.0",
        "input": binding,
        "input_hash": digest,
        "status": "succeeded" if succeeded else "failed",
        "scan": scan,
        "sarif_sha256": sha256_file(sarif_path) if succeeded else None,
    }
    write_json(manifest_path, manifest)
    if succeeded:
        return {
            "status": "succeeded",
            "sarif": sarif_path,
            "manifest": manifest_path,
            "cached": False,
        }
    return {"status": "failed", "manifest": manifest_path, "cached": False}


def _scan_resilient(
    repo: Path,
    executable: Path,
    database: Path,
    ram_mb: int,
    timeout_seconds: int,
    batch_root: Path,
    batch_input_hash: str,
    queries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result = _scan_chunk(
        repo,
        executable,
        database,
        ram_mb,
        timeout_seconds,
        batch_root,
        batch_input_hash,
        queries,
    )
    if result["status"] == "succeeded":
        return [{"queries": queries, **result}], []
    if len(queries) == 1:
        return [], [{"query": queries[0], "failure_manifest": result["manifest"]}]
    midpoint = len(queries) // 2
    left_ok, left_bad = _scan_resilient(
        repo,
        executable,
        database,
        ram_mb,
        timeout_seconds,
        batch_root,
        batch_input_hash,
        queries[:midpoint],
    )
    right_ok, right_bad = _scan_resilient(
        repo,
        executable,
        database,
        ram_mb,
        timeout_seconds,
        batch_root,
        batch_input_hash,
        queries[midpoint:],
    )
    return left_ok + right_ok, left_bad + right_bad


def _merge_sarif(paths: list[Path]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }
    for path in paths:
        merged["runs"].extend(_json(path).get("runs", []))
    return merged


def _validate_final_cache(
    manifest_path: Path,
    sarif_path: Path,
    input_payload: dict[str, Any],
    input_hash: str,
) -> dict[str, Any] | None:
    if not manifest_path.is_file():
        return None
    manifest = _json(manifest_path)
    if (
        manifest.get("batch_input_hash") != input_hash
        or manifest.get("input") != input_payload
    ):
        raise ValueError(f"batch cache input binding differs: {manifest_path}")
    if manifest.get("status") == "FAILED_ALL_QUARANTINED":
        return None
    if manifest.get("status") not in {"COMPLETE", "PARTIAL"}:
        raise ValueError(f"unknown batch cache status: {manifest_path}")
    if (
        not sarif_path.is_file()
        or manifest.get("batch_sarif_sha256") != sha256_file(sarif_path)
    ):
        raise ValueError(f"batch cache SARIF binding differs: {manifest_path}")
    return manifest


def _split_sarif(
    sarif: dict[str, Any],
    records: list[dict[str, Any]],
    repo: Path,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        rule_ids = set(record["rule_ids"])
        document = copy.deepcopy(sarif)
        total = 0
        for run in document.get("runs", []):
            results = []
            for source in run.get("results", []):
                if source.get("ruleId") not in rule_ids:
                    continue
                result = copy.deepcopy(source)
                result.pop("ruleIndex", None)
                results.append(result)
            run["results"] = results
            total += len(results)
            driver = (run.get("tool") or {}).get("driver") or {}
            if isinstance(driver.get("rules"), list):
                driver["rules"] = [
                    item for item in driver["rules"] if item.get("id") in rule_ids
                ]
        manifest_path = record["round_manifest_path"]
        paths = _paths(repo, manifest_path, record["round_manifest"])
        write_json(paths["sarif"], document)
        counts[record["pattern_id"]] = total
    return counts


def run_batch_scan(
    repo: Path,
    campaign_id: str,
    round_number: int,
    normalize: bool = True,
) -> dict[str, Any]:
    records = _scan_eligible_records(repo, campaign_id, round_number)
    if not records:
        raise ValueError("no preflight-passing, remote-scope-verified CodeQL rules are ready")
    config = yaml.safe_load((repo / "config" / "codeql.yaml").read_text(encoding="utf-8"))
    executable = repo / config["bundle"]["local_path"]
    if executable.is_dir():
        executable = executable / "codeql"
    if not executable.is_file():
        raise FileNotFoundError(f"pinned CodeQL executable is missing: {executable}")
    database = repo / config["database"]["path"]
    if not database.is_dir():
        raise FileNotFoundError(f"pinned CodeQL database is missing: {database}")
    scan_config = config.get("scan", {})
    batch_size = int(scan_config.get("batch_size", 16))
    if not 1 <= batch_size <= 64:
        raise ValueError("CodeQL batch_size must be between 1 and 64")
    input_payload = _input_payload(repo, config, database, records)
    input_hash = sha256_bytes(canonical_json(input_payload))
    output_root = (
        repo
        / "analysis"
        / "codeql"
        / campaign_id
        / f"round-{round_number}-batch"
        / input_hash
    )
    output_root.mkdir(parents=True, exist_ok=True)
    sarif_path = output_root / "all-patterns.sarif"
    manifest_path = output_root / "manifest.json"
    cached = _validate_final_cache(manifest_path, sarif_path, input_payload, input_hash)
    if cached is not None:
        _split_sarif(_json(sarif_path), records, repo)
        if normalize:
            for record in records:
                paths = _paths(
                    repo, record["round_manifest_path"], record["round_manifest"]
                )
                normalize_sarif(
                    paths["sarif"],
                    campaign_id,
                    record["pattern_id"],
                    paths["candidate_dir"],
                )
        return cached

    queries = sorted(
        [query for record in records for query in record["queries"]],
        key=lambda item: (item["rule_id"], str(item["path"])),
    )
    successful: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    for offset in range(0, len(queries), batch_size):
        ok, bad = _scan_resilient(
            repo,
            executable,
            database,
            int(scan_config.get("ram_mb", 4096)),
            int(scan_config.get("batch_chunk_timeout_seconds", 1800)),
            output_root,
            input_hash,
            queries[offset : offset + batch_size],
        )
        successful.extend(ok)
        quarantined.extend(bad)
    sarif = _merge_sarif([item["sarif"] for item in successful])
    write_json(sarif_path, sarif)
    result_counts = _split_sarif(sarif, records, repo)
    candidate_counts: dict[str, int] = {}
    if normalize:
        for record in records:
            paths = _paths(repo, record["round_manifest_path"], record["round_manifest"])
            written = normalize_sarif(
                paths["sarif"], campaign_id, record["pattern_id"], paths["candidate_dir"]
            )
            candidate_counts[record["pattern_id"]] = len(written)
    quarantined_rules = {item["query"]["rule_id"] for item in quarantined}
    manifest = {
        "schema_version": "1.0.0",
        "campaign_id": campaign_id,
        "round": round_number,
        "status": (
            "FAILED_ALL_QUARANTINED"
            if not successful
            else "PARTIAL" if quarantined else "COMPLETE"
        ),
        "batch_input_hash": input_hash,
        "input": input_payload,
        "batch_sarif": str(sarif_path),
        "batch_sarif_sha256": sha256_file(sarif_path),
        "pattern_count": len(records),
        "query_count": len(queries),
        "scanned_query_count": sum(len(item["queries"]) for item in successful),
        "quarantined_query_count": len(quarantined),
        "successful_chunks": [str(item["manifest"]) for item in successful],
        "quarantined": [
            {
                **_query_binding(repo, item["query"]),
                "failure_manifest": str(item["failure_manifest"]),
            }
            for item in quarantined
        ],
        "patterns": [
            {
                "pattern_id": record["pattern_id"],
                "artifact_path": str(record["artifact_path"]),
                "artifact_sha256": record["artifact_sha256"],
                "semantic_review_path": str(record["semantic_review_path"]),
                "semantic_review_sha256": record["semantic_review_sha256"],
                "semantic_status": record["semantic_status"],
                "scan_admission": record["scan_admission"],
                "rule_ids": record["rule_ids"],
                "quarantined_rule_ids": sorted(
                    set(record["rule_ids"]) & quarantined_rules
                ),
                "result_count": result_counts[record["pattern_id"]],
                "candidate_count": candidate_counts.get(record["pattern_id"]),
                "round_manifest": str(record["round_manifest_path"]),
            }
            for record in records
        ],
    }
    write_json(manifest_path, manifest)
    if not successful:
        raise RuntimeError(f"all CodeQL queries were quarantined; see {manifest_path}")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan preflight-passing, remote-scope-verified KNFSd rules in isolated batches."
    )
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--round", type=int, default=1)
    parser.add_argument("--no-normalize", action="store_true")
    args = parser.parse_args()
    result = run_batch_scan(
        args.repo.resolve(),
        args.campaign_id,
        args.round,
        normalize=not args.no_normalize,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
