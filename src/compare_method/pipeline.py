from __future__ import annotations

import argparse
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml
from jsonschema import Draft202012Validator

from .codeql_artifact import materialize, validate_artifact, verify_pack
from .codex_job import run_job
from .common import repo_root, sha256_file, write_json
from .context_pack import build_context_pack
from .dataset_split import build_split, partition_map


ACTIVE_MAPPING = {"direct", "semantic", "conditional"}
ACTIVE_PROTOCOLS = {"nfs3", "nfs4.0", "nfs4.1", "nfs4.2"}
STAGES = (
    "extraction",
    "extraction-review",
    "mapping",
    "context",
    "mapping-review",
    "pattern",
    "pattern-review",
    "rule-plan",
    "codeql-fast-author",
    "codeql-fast-gate",
    "codeql-author",
    "codeql-review",
    "codeql-materialize",
)


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _campaign_dir(repo: Path, campaign_id: str) -> Path:
    if not re.fullmatch(r"CAMPAIGN-[A-Z0-9-]+", campaign_id):
        raise ValueError("campaign ID must match CAMPAIGN-[A-Z0-9-]+")
    return repo / "campaigns" / campaign_id


def init_campaign(repo: Path, campaign_id: str) -> dict[str, Any]:
    directory = _campaign_dir(repo, campaign_id)
    manifest_path = directory / "manifest.json"
    if manifest_path.exists():
        return _json(manifest_path)
    private_path = directory / "control" / "dataset-split.private.json"
    public_path = directory / "dataset-split.public.json"
    build_split(repo, private_path, public_path)
    llm = yaml.safe_load((repo / "config" / "llm.yaml").read_text(encoding="utf-8"))
    manifest = {
        "schema_version": "1.0.0",
        "campaign_id": campaign_id,
        "target": {
            "name": "linux-knfsd",
            "kernel_ref": "v7.3",
            "kernel_commit": "c03c1a14507dfaf8b856c2608f9ac216021fc222",
            "protocols": ["nfs3", "nfs4.0", "nfs4.1", "nfs4.2"],
            "remote_entry_only": True,
        },
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "split": {
            "private_path": str(private_path.relative_to(repo)),
            "private_sha256": sha256_file(private_path),
            "public_path": str(public_path.relative_to(repo)),
            "public_sha256": sha256_file(public_path),
        },
        "llm": {
            "model": llm["model"],
            "reasoning_effort": llm["reasoning_effort"],
            "cyber_access_program": llm["cyber_access_program"],
        },
        "status": "active",
    }
    schema = _json(repo / "schemas" / "campaign.schema.json")
    Draft202012Validator(schema).validate(manifest)
    write_json(manifest_path, manifest)
    return manifest


def _split(repo: Path, campaign: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    path = repo / campaign["split"]["private_path"]
    if sha256_file(path) != campaign["split"]["private_sha256"]:
        raise ValueError("private split manifest hash changed after campaign initialization")
    return path, _json(path)


def _source_is_v2_only(case: dict[str, Any]) -> bool:
    text = " ".join(case["facts"].get("protocol_versions_raw", [])).lower()
    says_v2 = "nfsv2" in text or "nfs v2" in text or re.search(r"\bv2\b", text)
    says_active = any(token in text for token in ("nfsv3", "nfs v3", "v3", "nfsv4", "nfs v4", "v4", "rpc", "xdr"))
    return bool(says_v2 and not says_active)


def selected_case_paths(
    repo: Path, campaign: dict[str, Any], partition: str
) -> tuple[list[Path], int]:
    _, private = _split(repo, campaign)
    assignments = partition_map(private)
    paths = []
    excluded_v2 = 0
    for path in sorted((repo / "data" / "cases").glob("*.json")):
        case = _json(path)
        case_partition = assignments.get(case["case_id"])
        selected = (
            case_partition in {"development", "external_analogue"}
            if partition == "development"
            else case_partition == partition
        )
        if not selected:
            continue
        if _source_is_v2_only(case):
            excluded_v2 += 1
            continue
        paths.append(path)
    return paths, excluded_v2


def _latest(directory: Path, pattern: str) -> Path | None:
    paths = list(directory.glob(pattern))
    def key(path: Path) -> tuple[int, str]:
        match = re.match(r"v(\d+)", path.name)
        return (int(match.group(1)) if match else -1, path.name)
    return max(paths, key=key) if paths else None


def _codeql_preflight(repo: Path, artifact_path: Path) -> Path:
    """Compile and qltest a proposed artifact before independent review.

    The content hash makes each preflight immutable and prevents a reviewer
    correction from colliding with the final accepted pack location.
    """
    digest = sha256_file(artifact_path)
    output_root = repo / "analysis" / "codeql-preflight" / digest
    artifact = _json(artifact_path)
    pack_dir = (
        output_root
        / artifact["pattern_id"]
        / f"v{artifact['artifact_version']}"
    )
    verification = pack_dir / "verification.json"
    if verification.is_file():
        return verification
    pack_dir, _ = materialize(
        repo,
        artifact_path,
        output_root,
        allow_proposed=True,
    )
    verify_pack(repo, pack_dir)
    return pack_dir / "verification.json"


def _evidence_inputs(repo: Path, case_id: str) -> list[Path]:
    directory = repo / "evidence" / "cases" / case_id
    if not directory.is_dir():
        return []
    allowed_suffixes = {".txt", ".html", ".htm", ".md", ".json", ".patch", ".diff", ".pdf"}
    return [
        path
        for path in sorted(directory.rglob("*"))
        if path.is_file()
        and not path.name.endswith(".audit.json")
        and path.suffix.lower() in allowed_suffixes
        and path.stat().st_size <= 5_000_000
    ]


def _has_payload_evidence(paths: list[Path]) -> bool:
    return any(path.name != "manifest.json" for path in paths)


def _case_state(repo: Path, case_path: Path) -> dict[str, Any]:
    case = _json(case_path)
    case_id = case["case_id"]
    extraction_dir = repo / "analysis" / "extractions" / case_id
    extraction_candidates = [
        path for path in extraction_dir.glob("v[0-9]*.json")
        if not path.name.endswith(".reviewed.json") and not path.name.endswith(".audit.json")
    ]
    extraction = max(
        extraction_candidates,
        key=lambda path: int(re.match(r"v(\d+)", path.name).group(1)),
        default=None,
    )
    reviewed_extraction = _latest(extraction_dir, "v[0-9]*.reviewed.json")
    mapping_dir = repo / "mappings" / case_id
    mapping_candidates = [
        path for path in mapping_dir.glob("v[0-9]*.json")
        if not path.name.endswith(".reviewed.json") and not path.name.endswith(".audit.json")
    ]
    mapping = max(
        mapping_candidates,
        key=lambda path: int(re.match(r"v(\d+)", path.name).group(1)),
        default=None,
    )
    reviewed_mapping = _latest(mapping_dir, "v[0-9]*.reviewed.json")
    context = _latest(repo / "target-map" / "context" / case_id, "v[0-9]*.json")
    return {
        "case_id": case_id,
        "case_path": case_path,
        "evidence": _evidence_inputs(repo, case_id),
        "extraction": extraction,
        "reviewed_extraction": reviewed_extraction,
        "mapping": mapping,
        "context": context,
        "reviewed_mapping": reviewed_mapping,
    }


def _next_version(directory: Path, suffix: str = ".json") -> int:
    versions = []
    for path in directory.glob(f"v[0-9]*{suffix}"):
        match = re.match(r"v(\d+)", path.name)
        if match:
            versions.append(int(match.group(1)))
    return max(versions, default=0) + 1


def _active_mapping(path: Path | None) -> bool:
    if path is None:
        return False
    review = _json(path)
    protocols = set(review["verified_target_semantics"]["protocol_versions"])
    return bool(
        review["review_status"] == "accepted"
        and review["applicability_status"] in ACTIVE_MAPPING
        and review["verified_target_semantics"]["remote_reachable"] is True
        and protocols & ACTIVE_PROTOCOLS
        and protocols != {"nfs2"}
    )


def _pattern_group_key(extraction: dict[str, Any], mapping: dict[str, Any]) -> str:
    model = extraction["vulnerability_model"]
    raw = "|".join(
        [
            str(model.get("root_cause") or "unknown"),
            mapping.get("transferred_invariant") or "unknown",
            ",".join(sorted(mapping["verified_target_semantics"]["protocol_versions"])),
        ]
    ).lower()
    normalized = re.sub(r"\s+", " ", raw).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16].upper()


def build_pattern_groups(repo: Path, campaign: dict[str, Any]) -> list[Path]:
    case_paths, _ = selected_case_paths(repo, campaign, "development")
    groups: dict[str, list[dict[str, Any]]] = {}
    for case_path in case_paths:
        state = _case_state(repo, case_path)
        if not _active_mapping(state["reviewed_mapping"]) or state["reviewed_extraction"] is None:
            continue
        extraction = _json(state["reviewed_extraction"])
        mapping = _json(state["reviewed_mapping"])
        key = _pattern_group_key(extraction, mapping)
        groups.setdefault(key, []).append(
            {
                "case_id": state["case_id"],
                "extraction_path": str(state["reviewed_extraction"].relative_to(repo)),
                "extraction_sha256": sha256_file(state["reviewed_extraction"]),
                "mapping_path": str(state["reviewed_mapping"].relative_to(repo)),
                "mapping_sha256": sha256_file(state["reviewed_mapping"]),
                "context_path": str(state["context"].relative_to(repo)) if state["context"] else None,
                "context_sha256": sha256_file(state["context"]) if state["context"] else None,
            }
        )
    directory = _campaign_dir(repo, campaign["campaign_id"]) / "groups"
    outputs = []
    for key, members in sorted(groups.items()):
        path = directory / f"GROUP-{key}.json"
        write_json(
            path,
            {
                "schema_version": "1.0.0",
                "campaign_id": campaign["campaign_id"],
                "pattern_group_id": f"GROUP-{key}",
                "partition": "development",
                "members": sorted(members, key=lambda item: item["case_id"]),
            },
        )
        outputs.append(path)
    return outputs


def _run_role(
    role: str,
    repo: Path,
    inputs: list[Path],
    output: Path,
    dry_run: bool,
    split_manifest: Path | None = None,
) -> bool:
    if output.exists() and not dry_run:
        return False
    code = run_job(role, repo, inputs, output, dry_run, split_manifest)
    if code:
        raise RuntimeError(f"{role} failed for {output} with exit code {code}")
    return True


def _run_role_batch(
    jobs: list[tuple[str, list[Path], Path]],
    repo: Path,
    dry_run: bool,
    split_manifest: Path | None,
    workers: int,
) -> int:
    if workers < 1:
        raise ValueError("workers must be at least 1")
    if not jobs:
        return 0

    def execute(job: tuple[str, list[Path], Path]) -> bool:
        role, inputs, output = job
        return _run_role(role, repo, inputs, output, dry_run, split_manifest)

    if workers == 1:
        return sum(execute(job) for job in jobs)
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as executor:
        return sum(executor.map(execute, jobs))


def run_case_stage(
    repo: Path,
    campaign: dict[str, Any],
    stage: str,
    partition: str,
    max_jobs: int,
    dry_run: bool,
    allow_fact_only: bool = False,
    workers: int = 1,
) -> dict[str, Any]:
    split_path, _ = _split(repo, campaign)
    case_paths, excluded_v2 = selected_case_paths(repo, campaign, partition)
    attempted = completed = blocked = skipped = 0
    reasons: dict[str, int] = {}
    pending_roles: list[tuple[str, list[Path], Path]] = []
    kernel_source = repo / "kernel" / "linux-v7.3"

    for case_path in case_paths:
        if attempted >= max_jobs:
            break
        state = _case_state(repo, case_path)
        case_id = state["case_id"]
        inputs: list[Path]
        output: Path
        role: str | None = None
        block_reason: str | None = None

        if stage == "extraction":
            if state["reviewed_extraction"] and _json(state["reviewed_extraction"])["status"] in {"accepted", "insufficient_evidence", "rejected"}:
                skipped += 1
                continue
            if not allow_fact_only and not _has_payload_evidence(state["evidence"]):
                block_reason = "missing_source_evidence"
                output = repo / "analysis" / "extractions" / case_id / "v1.json"
                inputs = []
                role = "extractor"
            else:
                version = _next_version(repo / "analysis" / "extractions" / case_id)
                output = repo / "analysis" / "extractions" / case_id / f"v{version}.json"
                inputs = [case_path, *state["evidence"]]
                role = "extractor"
        elif stage == "extraction-review":
            if state["extraction"] is None:
                block_reason = "missing_extraction"
            elif state["reviewed_extraction"] and state["reviewed_extraction"].stem.startswith(state["extraction"].stem):
                skipped += 1
                continue
            else:
                output = state["extraction"].with_name(state["extraction"].stem + ".reviewed.json")
                inputs = [case_path, state["extraction"], *state["evidence"]]
                role = "extraction-reviewer"
        elif stage == "mapping":
            if state["reviewed_extraction"] is None:
                block_reason = "missing_reviewed_extraction"
            elif _json(state["reviewed_extraction"])["status"] != "accepted":
                block_reason = "extraction_not_accepted"
            elif state["mapping"] is not None:
                skipped += 1
                continue
            else:
                output = repo / "mappings" / case_id / "v1.json"
                inputs = [
                    case_path,
                    state["reviewed_extraction"],
                    repo / "config" / "target-knfsd-v7.3.yaml",
                    repo / "registry" / "nfs-semantics.yaml",
                    repo / "registry" / "vulnerability-taxonomy.yaml",
                ]
                role = "mapper"
        elif stage == "context":
            if state["mapping"] is None:
                block_reason = "missing_mapping"
            elif not kernel_source.is_dir():
                block_reason = "missing_exact_v7.3_kernel_source"
            elif state["context"] is not None:
                skipped += 1
                continue
            else:
                attempted += 1
                output = repo / "target-map" / "context" / case_id / "v1.json"
                if dry_run:
                    completed += 1
                    continue
                result = build_context_pack(
                    state["mapping"],
                    kernel_source,
                    "c03c1a14507dfaf8b856c2608f9ac216021fc222",
                )
                write_json(output, result)
                completed += 1
                continue
        elif stage == "mapping-review":
            if state["mapping"] is None or state["context"] is None or state["reviewed_extraction"] is None:
                block_reason = "missing_mapping_context_or_extraction"
            elif state["reviewed_mapping"] is not None:
                skipped += 1
                continue
            else:
                output = state["mapping"].with_name(state["mapping"].stem + ".reviewed.json")
                inputs = [
                    case_path,
                    state["reviewed_extraction"],
                    state["mapping"],
                    state["context"],
                    repo / "config" / "target-knfsd-v7.3.yaml",
                ]
                role = "mapping-reviewer"
        else:
            raise ValueError(f"not a case stage: {stage}")

        if block_reason:
            blocked += 1
            reasons[block_reason] = reasons.get(block_reason, 0) + 1
            continue
        attempted += 1
        pending_roles.append((role, inputs, output))

    completed += _run_role_batch(
        pending_roles,
        repo,
        dry_run,
        split_path,
        workers,
    )

    return {
        "stage": stage,
        "partition": partition,
        "selected_cases": len(case_paths),
        "excluded_v2_only": excluded_v2,
        "attempted": attempted,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "blocked_reasons": reasons,
        "dry_run": dry_run,
        "allow_fact_only": allow_fact_only,
        "workers": workers,
    }


def _group_state(repo: Path, group_path: Path) -> dict[str, Any]:
    group_id = group_path.stem
    directory = repo / "patterns" / "groups" / group_id
    proposed: list[tuple[int, Path]] = []
    reviewed: list[tuple[int, Path]] = []
    for path in directory.glob("codeql-v*.json"):
        if path.name.endswith(".audit.json"):
            continue
        match = re.fullmatch(r"codeql-v(\d+)(\.reviewed)?\.json", path.name)
        if not match:
            continue
        target = reviewed if match.group(2) else proposed
        target.append((int(match.group(1)), path))
    return {
        "group": _json(group_path),
        "group_path": group_path,
        "directory": directory,
        "pattern": directory / "v1.json",
        "reviewed_pattern": directory / "v1.reviewed.json",
        "rule_plan": directory / "rule-plan-v1.json",
        "fast_bundle": directory / "fast-bundle-v1.json",
        "codeql": max(proposed)[1] if proposed else None,
        "codeql_version": max(proposed)[0] if proposed else 0,
        "reviewed_codeql": max(reviewed)[1] if reviewed else None,
        "reviewed_codeql_version": max(reviewed)[0] if reviewed else 0,
    }


def _pattern_input(state: dict[str, Any]) -> Path | None:
    if state["reviewed_pattern"].is_file():
        return state["reviewed_pattern"]
    if state["pattern"].is_file():
        return state["pattern"]
    return None


def _write_immutable_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_file():
        if _json(path) != value:
            raise ValueError(f"refusing to overwrite a different derived artifact: {path}")
        return
    write_json(path, value)


def _derive_fast_bundle(repo: Path, state: dict[str, Any]) -> None:
    """Split one LLM response into the existing versioned plan/artifact files."""
    bundle_path = state["fast_bundle"]
    bundle = _json(bundle_path)
    plan = bundle["rule_plan"]
    artifact = bundle["codeql_artifact"]
    pattern_path = _pattern_input(state)
    if pattern_path is None:
        raise ValueError("fast bundle has no Pattern IR")
    pattern = _json(pattern_path)
    pattern_id = pattern["pattern_id"]
    if plan["pattern_id"] != pattern_id or artifact["pattern_id"] != pattern_id:
        raise ValueError("fast bundle pattern IDs do not match its Pattern IR")
    if plan["pattern_ir_version"] != artifact["pattern_ir_version"]:
        raise ValueError("fast bundle Pattern IR versions disagree")
    if plan["rule_plan_version"] != artifact["rule_plan_version"]:
        raise ValueError("fast bundle rule plan versions disagree")
    plan_schema = _json(repo / "schemas" / "rule-plan.schema.json")
    Draft202012Validator(plan_schema).validate(plan)
    validate_artifact(repo, artifact, allow_proposed=True)
    plan_rule_ids = {item["rule_id"] for item in plan["rule_variants"]}
    query_rule_ids = {item["rule_id"] for item in artifact["queries"]}
    if not query_rule_ids <= plan_rule_ids:
        raise ValueError("fast bundle contains CodeQL rule IDs absent from its rule plan")
    for query in artifact["queries"]:
        metadata_id = re.search(r"(?m)^\s*\*?\s*@id\s+(\S+)\s*$", query["content"])
        if metadata_id is None or metadata_id.group(1) != query["rule_id"]:
            raise ValueError(
                f"fast query {query['path']} must use rule_id as its CodeQL @id"
            )
    _write_immutable_json(state["rule_plan"], plan)
    codeql_path = state["directory"] / "codeql-v1.json"
    _write_immutable_json(codeql_path, artifact)
    _write_immutable_json(
        bundle_path.with_suffix(bundle_path.suffix + ".derived.json"),
        {
            "schema_version": "1.0.0",
            "source_bundle": str(bundle_path),
            "source_bundle_sha256": sha256_file(bundle_path),
            "pattern_input": str(pattern_path),
            "pattern_input_sha256": sha256_file(pattern_path),
            "rule_plan": str(state["rule_plan"]),
            "rule_plan_sha256": sha256_file(state["rule_plan"]),
            "codeql_artifact": str(codeql_path),
            "codeql_artifact_sha256": sha256_file(codeql_path),
        },
    )


def _fast_gate_artifact(repo: Path, state: dict[str, Any], dry_run: bool) -> str:
    """Accept passing initial rules without a second LLM call; retain failures for repair."""
    artifact_path = state["codeql"]
    if artifact_path is None:
        return "missing"
    output = state["directory"] / f"codeql-v{state['codeql_version']}.reviewed.json"
    if output.is_file():
        return _json(output)["status"]
    if dry_run:
        return "dry_run"
    preflight = _codeql_preflight(repo, artifact_path)
    verification = _json(preflight)
    gate = verification.get("gate", {})
    passed = gate.get("compiled") is True and gate.get("qltests_passed") is True
    artifact = _json(artifact_path)
    artifact["status"] = "accepted" if passed else "needs_revision"
    artifact["review_notes"] = [
        *artifact.get("review_notes", []),
        (
            "deterministic fast gate: "
            f"compiled={bool(gate.get('compiled'))}, "
            f"qltests_passed={bool(gate.get('qltests_passed'))}, "
            f"verification_sha256={sha256_file(preflight)}"
        ),
    ]
    validate_artifact(repo, artifact, allow_proposed=not passed)
    _write_immutable_json(output, artifact)
    _write_immutable_json(
        output.with_suffix(output.suffix + ".audit.json"),
        {
            "schema_version": "1.0.0",
            "role": "deterministic-fast-gate",
            "input": {"path": str(artifact_path), "sha256": sha256_file(artifact_path)},
            "preflight": {"path": str(preflight), "sha256": sha256_file(preflight)},
            "decision": artifact["status"],
        },
    )
    if passed:
        pack_dir, _ = materialize(repo, output, repo / "codeql" / "generated")
        final = verify_pack(repo, pack_dir)
        final_gate = final["gate"]
        if not final_gate["compiled"] or not final_gate["qltests_passed"]:
            raise RuntimeError(f"final fast gate changed result for {artifact['pattern_id']}")
    return artifact["status"]


def _run_fast_author_stage(
    repo: Path,
    campaign: dict[str, Any],
    groups: list[Path],
    max_jobs: int,
    dry_run: bool,
    workers: int,
) -> dict[str, Any]:
    split_path, _ = _split(repo, campaign)
    attempted = completed = blocked = skipped = 0
    reasons: dict[str, int] = {}
    jobs: list[tuple[str, list[Path], Path]] = []
    selected_states: list[dict[str, Any]] = []
    for group_path in groups:
        state = _group_state(repo, group_path)
        if state["codeql"] is not None and state["rule_plan"].is_file():
            skipped += 1
            continue
        if state["fast_bundle"].is_file():
            _derive_fast_bundle(repo, state)
            completed += 1
            continue
        if attempted >= max_jobs:
            break
        pattern_path = _pattern_input(state)
        contexts = [
            repo / item["context_path"]
            for item in state["group"]["members"]
            if item["context_path"]
        ]
        if pattern_path is None:
            blocked += 1
            reasons["missing_pattern"] = reasons.get("missing_pattern", 0) + 1
            continue
        if not contexts:
            blocked += 1
            reasons["missing_context"] = reasons.get("missing_context", 0) + 1
            continue
        inputs = [
            pattern_path,
            *contexts,
            repo / "config" / "target-knfsd-v7.3.yaml",
            repo / "registry" / "nfs-semantics.yaml",
            repo / "registry" / "vulnerability-taxonomy.yaml",
        ]
        jobs.append(("codeql-fast-author", inputs, state["fast_bundle"]))
        selected_states.append(state)
        attempted += 1
    _run_role_batch(jobs, repo, dry_run, split_path, workers)
    if not dry_run:
        for state in selected_states:
            _derive_fast_bundle(repo, state)
            completed += 1
    else:
        completed += len(selected_states)
    return {
        "stage": "codeql-fast-author",
        "pattern_groups": len(groups),
        "attempted": attempted,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "blocked_reasons": reasons,
        "dry_run": dry_run,
        "workers": workers,
    }


def _run_fast_gate_stage(
    repo: Path,
    groups: list[Path],
    max_jobs: int,
    dry_run: bool,
) -> dict[str, Any]:
    attempted = completed = blocked = skipped = 0
    decisions = {"accepted": 0, "needs_revision": 0, "dry_run": 0}
    for group_path in groups:
        state = _group_state(repo, group_path)
        if state["codeql"] is None:
            blocked += 1
            continue
        if state["reviewed_codeql_version"] >= state["codeql_version"]:
            skipped += 1
            continue
        if attempted >= max_jobs:
            break
        attempted += 1
        decision = _fast_gate_artifact(repo, state, dry_run)
        if decision in decisions:
            decisions[decision] += 1
        completed += 1
    return {
        "stage": "codeql-fast-gate",
        "pattern_groups": len(groups),
        "attempted": attempted,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "decisions": decisions,
        "dry_run": dry_run,
        "workers": 1,
    }


def run_pattern_stage(
    repo: Path,
    campaign: dict[str, Any],
    stage: str,
    max_jobs: int,
    dry_run: bool,
    workers: int = 1,
) -> dict[str, Any]:
    split_path, _ = _split(repo, campaign)
    groups = build_pattern_groups(repo, campaign)
    if stage == "codeql-fast-author":
        return _run_fast_author_stage(repo, campaign, groups, max_jobs, dry_run, workers)
    if stage == "codeql-fast-gate":
        return _run_fast_gate_stage(repo, groups, max_jobs, dry_run)
    attempted = completed = blocked = skipped = 0
    reasons: dict[str, int] = {}
    pending_roles: list[tuple[str, list[Path], Path]] = []
    for group_path in groups:
        if attempted >= max_jobs:
            break
        state = _group_state(repo, group_path)
        members = state["group"]["members"]
        mapping_inputs = [repo / item["mapping_path"] for item in members]
        extraction_inputs = [repo / item["extraction_path"] for item in members]
        context_inputs = [repo / item["context_path"] for item in members if item["context_path"]]
        role: str | None = None
        block_reason: str | None = None
        if stage == "pattern":
            output = state["pattern"]
            inputs = [group_path, *extraction_inputs, *mapping_inputs]
            role = "pattern-clusterer"
        elif stage == "pattern-review":
            if not state["pattern"].is_file():
                block_reason = "missing_pattern"
            else:
                output = state["reviewed_pattern"]
                inputs = [group_path, state["pattern"], *mapping_inputs, *context_inputs]
                role = "pattern-reviewer"
        elif stage == "rule-plan":
            if not state["reviewed_pattern"].is_file():
                block_reason = "missing_reviewed_pattern"
            elif not context_inputs:
                block_reason = "missing_context"
            else:
                output = state["rule_plan"]
                inputs = [state["reviewed_pattern"], *context_inputs]
                role = "rule-planner"
        elif stage == "codeql-author":
            pattern_path = _pattern_input(state)
            if pattern_path is None or not state["rule_plan"].is_file():
                block_reason = "missing_pattern_or_rule_plan"
            elif state["codeql"] is None:
                output = state["directory"] / "codeql-v1.json"
                inputs = [pattern_path, state["rule_plan"], *context_inputs]
                role = "codeql-author"
            elif state["reviewed_codeql_version"] < state["codeql_version"]:
                skipped += 1
                continue
            else:
                review = _json(state["reviewed_codeql"])
                if review["status"] == "accepted":
                    skipped += 1
                    continue
                if review["status"] == "rejected":
                    block_reason = "codeql_rejected_quarantine"
                    output = state["directory"] / f"codeql-v{state['codeql_version'] + 1}.json"
                    inputs = []
                    role = "codeql-author"
                elif review["status"] != "needs_revision":
                    block_reason = f"unsupported_codeql_review_status:{review['status']}"
                    output = state["directory"] / f"codeql-v{state['codeql_version'] + 1}.json"
                    inputs = []
                    role = "codeql-author"
                else:
                    preflight = _codeql_preflight(repo, state["codeql"])
                    output = state["directory"] / f"codeql-v{state['codeql_version'] + 1}.json"
                    inputs = [
                        pattern_path,
                        state["rule_plan"],
                        state["codeql"],
                        state["reviewed_codeql"],
                        preflight,
                        *context_inputs,
                    ]
                role = "codeql-author"
        elif stage == "codeql-review":
            pattern_path = _pattern_input(state)
            if state["codeql"] is None:
                block_reason = "missing_codeql_artifact"
            elif pattern_path is None or not state["rule_plan"].is_file():
                block_reason = "missing_pattern_or_rule_plan"
            elif state["reviewed_codeql_version"] == state["codeql_version"]:
                skipped += 1
                continue
            else:
                output = state["directory"] / f"codeql-v{state['codeql_version']}.reviewed.json"
                preflight = _codeql_preflight(repo, state["codeql"])
                inputs = [
                    pattern_path,
                    state["rule_plan"],
                    state["codeql"],
                    preflight,
                    *context_inputs,
                ]
                role = "codeql-reviewer"
        elif stage == "codeql-materialize":
            if state["reviewed_codeql"] is None:
                block_reason = "missing_reviewed_codeql_artifact"
            else:
                artifact = _json(state["reviewed_codeql"])
                if artifact["status"] != "accepted":
                    block_reason = f"codeql_not_accepted:{artifact['status']}"
                    # The next codeql-author run consumes this review and creates a new version.
                    blocked += 1
                    reasons[block_reason] = reasons.get(block_reason, 0) + 1
                    continue
                output_dir = repo / "codeql" / "generated" / artifact["pattern_id"] / f"v{artifact['artifact_version']}"
                if (output_dir / "verification.json").is_file():
                    skipped += 1
                    continue
                attempted += 1
                if dry_run:
                    completed += 1
                    continue
                pack_dir, _ = materialize(repo, state["reviewed_codeql"], repo / "codeql" / "generated")
                verification = verify_pack(repo, pack_dir)
                gate = verification["gate"]
                if not gate["compiled"] or not gate["qltests_passed"]:
                    raise RuntimeError(
                        f"CodeQL compile/qltest gate failed for {artifact['pattern_id']}"
                    )
                completed += 1
                continue
        else:
            raise ValueError(f"not a pattern stage: {stage}")

        if block_reason:
            blocked += 1
            reasons[block_reason] = reasons.get(block_reason, 0) + 1
            continue
        if output.exists() and not dry_run:
            skipped += 1
            continue
        attempted += 1
        pending_roles.append((role, inputs, output))
    completed += _run_role_batch(
        pending_roles,
        repo,
        dry_run,
        split_path,
        workers,
    )
    return {
        "stage": stage,
        "pattern_groups": len(groups),
        "attempted": attempted,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "blocked_reasons": reasons,
        "dry_run": dry_run,
        "workers": workers,
    }


def campaign_status(repo: Path, campaign: dict[str, Any], partition: str) -> dict[str, Any]:
    paths, excluded = selected_case_paths(repo, campaign, partition)
    states = [_case_state(repo, path) for path in paths]
    groups = build_pattern_groups(repo, campaign) if partition == "development" else []
    group_states = [_group_state(repo, path) for path in groups]

    def verified(state: dict[str, Any]) -> bool:
        artifact_path = state["reviewed_codeql"]
        if artifact_path is None or not artifact_path.is_file():
            return False
        artifact = _json(artifact_path)
        verification = (
            repo
            / "codeql"
            / "generated"
            / artifact["pattern_id"]
            / f"v{artifact['artifact_version']}"
            / "verification.json"
        )
        if not verification.is_file():
            return False
        gate = _json(verification).get("gate", {})
        return gate.get("compiled") is True and gate.get("qltests_passed") is True

    return {
        "campaign_id": campaign["campaign_id"],
        "partition": partition,
        "selected_cases": len(paths),
        "excluded_v2_only": excluded,
        "case_stages": {
            "source_evidence_ready": sum(_has_payload_evidence(state["evidence"]) for state in states),
            "extracted": sum(state["extraction"] is not None for state in states),
            "extraction_reviewed": sum(state["reviewed_extraction"] is not None for state in states),
            "mapped": sum(state["mapping"] is not None for state in states),
            "context_built": sum(state["context"] is not None for state in states),
            "mapping_reviewed": sum(state["reviewed_mapping"] is not None for state in states),
            "active_mappings": sum(_active_mapping(state["reviewed_mapping"]) for state in states),
        },
        "pattern_groups": len(groups),
        "pattern_stages": {
            "pattern_proposed": sum(state["pattern"].is_file() for state in group_states),
            "pattern_reviewed": sum(state["reviewed_pattern"].is_file() for state in group_states),
            "rule_planned": sum(state["rule_plan"].is_file() for state in group_states),
            "codeql_authored": sum(state["codeql"] is not None for state in group_states),
            "codeql_reviewed": sum(state["reviewed_codeql"] is not None for state in group_states),
            "codeql_compile_qltest_passed": sum(verified(state) for state in group_states),
        },
        "runtime_note": "downstream scan/runtime/adjudication are admitted only after CodeQL compile and qltest gates",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the resumable KNFSD comparative-analysis campaign.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--campaign-id", required=True)
    status = sub.add_parser("status")
    status.add_argument("--campaign-id", required=True)
    status.add_argument("--partition", choices=("development", "validation", "sealed_holdout"), default="development")
    run = sub.add_parser("run")
    run.add_argument("--campaign-id", required=True)
    run.add_argument("--stage", choices=STAGES, required=True)
    run.add_argument("--partition", choices=("development", "validation", "sealed_holdout"), default="development")
    run.add_argument("--max-jobs", type=int, default=1)
    run.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Bounded isolated Codex workers; deterministic CodeQL gates remain serial",
    )
    run.add_argument("--dry-run", action="store_true")
    run.add_argument(
        "--allow-fact-only",
        action="store_true",
        help="Permit low-confidence extraction without fetched patch/reference evidence",
    )
    args = parser.parse_args()
    repo = args.repo.resolve()
    if args.command == "init":
        result = init_campaign(repo, args.campaign_id)
    else:
        campaign = _json(_campaign_dir(repo, args.campaign_id) / "manifest.json")
        if args.command == "status":
            result = campaign_status(repo, campaign, args.partition)
        elif args.stage in STAGES[:5]:
            result = run_case_stage(
                repo,
                campaign,
                args.stage,
                args.partition,
                args.max_jobs,
                args.dry_run,
                args.allow_fact_only,
                args.workers,
            )
        else:
            if args.partition != "development":
                raise ValueError("pattern/rule generation is Development-only")
            result = run_pattern_stage(
                repo,
                campaign,
                args.stage,
                args.max_jobs,
                args.dry_run,
                args.workers,
            )
        if args.command == "run":
            run_log = _campaign_dir(repo, args.campaign_id) / "runs" / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{args.stage}.json"
            write_json(run_log, result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
