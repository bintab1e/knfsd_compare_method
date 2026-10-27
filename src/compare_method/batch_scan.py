from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import yaml

from .candidate import normalize_sarif
from .codeql_artifact import _run
from .common import repo_root, sha256_file, write_json
from .pipeline import _campaign_dir, _group_state, _json, _pattern_input, build_pattern_groups
from .round_pipeline import _paths, init_round


def _accepted_records(repo: Path, campaign_id: str, round_number: int) -> list[dict[str, Any]]:
    campaign = _json(_campaign_dir(repo, campaign_id) / "manifest.json")
    records: list[dict[str, Any]] = []
    seen_rule_ids: dict[str, str] = {}
    for group_path in build_pattern_groups(repo, campaign):
        state = _group_state(repo, group_path)
        artifact_path = state["reviewed_codeql"]
        pattern_path = _pattern_input(state)
        if artifact_path is None or pattern_path is None or not state["rule_plan"].is_file():
            continue
        artifact = _json(artifact_path)
        if artifact["status"] != "accepted":
            continue
        pack_dir = (
            repo
            / "codeql"
            / "generated"
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
        query_paths = []
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
                raise FileNotFoundError(f"materialized query is missing: {query_path}")
            query_paths.append(query_path)
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
        )
        records.append(
            {
                "pattern_id": artifact["pattern_id"],
                "artifact_path": artifact_path,
                "artifact_sha256": sha256_file(artifact_path),
                "pack_dir": pack_dir,
                "query_paths": query_paths,
                "rule_ids": sorted(set(rule_ids)),
                "round_manifest_path": manifest_path,
                "round_manifest": manifest,
            }
        )
    return records


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
    records = _accepted_records(repo, campaign_id, round_number)
    if not records:
        raise ValueError("no accepted, compiled, qltest-passing CodeQL rules are ready")
    config = yaml.safe_load((repo / "config" / "codeql.yaml").read_text(encoding="utf-8"))
    executable = repo / config["bundle"]["local_path"]
    if executable.is_dir():
        executable = executable / "codeql"
    if not executable.is_file():
        raise FileNotFoundError(f"pinned CodeQL executable is missing: {executable}")
    database = repo / config["database"]["path"]
    if not database.is_dir():
        raise FileNotFoundError(f"pinned CodeQL database is missing: {database}")
    output_root = repo / "analysis" / "codeql" / campaign_id / f"round-{round_number}-batch"
    output_root.mkdir(parents=True, exist_ok=True)
    sarif_path = output_root / "all-patterns.sarif"
    verification_path = output_root / "verification.json"
    manifest_path = output_root / "manifest.json"
    query_paths = [path for record in records for path in record["query_paths"]]
    if not sarif_path.is_file():
        scan = _run(
            [
                str(executable),
                "database",
                "analyze",
                f"--ram={int(config.get('scan', {}).get('ram_mb', 4096))}",
                str(database),
                *[str(path) for path in query_paths],
                "--format=sarifv2.1.0",
                f"--output={sarif_path}",
                "--rerun",
            ],
            repo,
            timeout_seconds=int(config.get("scan", {}).get("batch_timeout_seconds", 7200)),
        )
        write_json(verification_path, scan)
        if scan["exit_code"] != 0 or not sarif_path.is_file():
            raise RuntimeError("batch CodeQL database analyze failed")
    sarif = _json(sarif_path)
    result_counts = _split_sarif(sarif, records, repo)
    candidate_counts: dict[str, int] = {}
    if normalize:
        for record in records:
            paths = _paths(repo, record["round_manifest_path"], record["round_manifest"])
            written = normalize_sarif(
                paths["sarif"], campaign_id, record["pattern_id"], paths["candidate_dir"]
            )
            candidate_counts[record["pattern_id"]] = len(written)
    manifest = {
        "schema_version": "1.0.0",
        "campaign_id": campaign_id,
        "round": round_number,
        "database": str(database),
        "database_expected_source_commit": config["database"]["expected_source_commit"],
        "batch_sarif": str(sarif_path),
        "batch_sarif_sha256": sha256_file(sarif_path),
        "pattern_count": len(records),
        "query_count": len(query_paths),
        "patterns": [
            {
                "pattern_id": record["pattern_id"],
                "artifact_path": str(record["artifact_path"]),
                "artifact_sha256": record["artifact_sha256"],
                "rule_ids": record["rule_ids"],
                "result_count": result_counts[record["pattern_id"]],
                "candidate_count": candidate_counts.get(record["pattern_id"]),
                "round_manifest": str(record["round_manifest_path"]),
            }
            for record in records
        ],
    }
    write_json(manifest_path, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan all accepted KNFSd rules in one CodeQL invocation.")
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
