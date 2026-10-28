from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .adjudication_bundle import build_bundles
from .candidate import normalize_sarif
from .codeql_artifact import materialize, verify_pack
from .codex_job import run_job
from .common import repo_root, sha256_file, write_json
from .round_result import build_round_result
from .runtime_dispatch import run_dispatch
from .pipeline import semantic_scan_admission


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _relative(repo: Path, path: Path) -> str:
    return str(path.resolve().relative_to(repo))


def _bound(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": sha256_file(path)}


def init_round(
    repo: Path,
    campaign_id: str,
    round_number: int,
    pattern_ir: Path,
    rule_plan: Path,
    codeql_artifact: Path,
    context_paths: list[Path],
    semantic_review: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    pattern = _json(pattern_ir)
    artifact = _json(codeql_artifact)
    if pattern["pattern_id"] != artifact["pattern_id"]:
        raise ValueError("Pattern IR and CodeQL artifact identify different patterns")
    pattern_id = pattern["pattern_id"]
    directory = repo / "campaigns" / campaign_id / "patterns" / pattern_id / f"round-{round_number}"
    manifest_path = directory / "manifest.json"
    inputs = {
        "pattern_ir": _bound(pattern_ir),
        "rule_plan": _bound(rule_plan),
        "codeql_artifact": _bound(codeql_artifact),
        "semantic_review": _bound(semantic_review) if semantic_review else None,
        "contexts": [
            _bound(path)
            for path in sorted(context_paths, key=lambda item: str(item.resolve()))
        ],
    }
    if manifest_path.exists():
        existing = _json(manifest_path)
        identity = {
            "campaign_id": campaign_id,
            "pattern_id": pattern_id,
            "round": round_number,
            "inputs": inputs,
        }
        actual = {key: existing.get(key) for key in identity}
        if actual != identity:
            raise ValueError(
                f"existing round manifest input binding differs: {manifest_path}"
            )
        return manifest_path, existing
    manifest = {
        "schema_version": "1.0.0",
        "campaign_id": campaign_id,
        "pattern_id": pattern_id,
        "round": round_number,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inputs": inputs,
        "status": "active",
    }
    write_json(manifest_path, manifest)
    return manifest_path, manifest


def _resolve(repo: Path, binding: dict[str, str]) -> Path:
    path = Path(binding["path"])
    path = path if path.is_absolute() else repo / path
    if sha256_file(path) != binding["sha256"]:
        raise ValueError(f"round input changed: {path}")
    return path


def _paths(repo: Path, manifest_path: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    campaign = manifest["campaign_id"]
    pattern = manifest["pattern_id"]
    round_number = manifest["round"]
    round_name = f"round-{round_number}"
    return {
        "manifest": manifest_path,
        "sarif": repo / "analysis" / "codeql" / pattern / f"{round_name}.sarif",
        "candidate_dir": repo / "candidates" / campaign / pattern / round_name,
        "job_root": repo / "validation" / "jobs" / campaign / pattern / round_name,
        "validation_root": repo / "validation" / "runs" / campaign / pattern / round_name,
        "bundle_dir": repo / "analysis" / "bundles" / campaign / pattern / round_name,
        "verdict_dir": repo / "analysis" / "verdicts" / campaign / pattern / round_name,
        "round_result": repo / "analysis" / "rounds" / pattern / f"{round_name}.json",
        "refinement": repo / "analysis" / "refinements" / pattern / f"after-{round_name}.json",
    }


def round_status(repo: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    candidate_count = len(list(paths["candidate_dir"].glob("CANDIDATE-*.json")))
    jobs = {
        sanitizer: len(list(paths["job_root"].glob(f"CANDIDATE-*/{sanitizer}.json")))
        for sanitizer in ("kasan", "kcsan")
    }
    verdict_count = len(list(paths["verdict_dir"].glob("CANDIDATE-*.json")))
    return {
        "campaign_id": manifest["campaign_id"],
        "pattern_id": manifest["pattern_id"],
        "round": manifest["round"],
        "gates": {
            "codeql_scan": paths["sarif"].is_file(),
            "candidates_normalized": (paths["candidate_dir"] / "candidates.jsonl").is_file(),
            "validation_jobs": jobs,
            "kasan_result": (paths["validation_root"] / "kasan" / "result.json").is_file(),
            "kcsan_result": (paths["validation_root"] / "kcsan" / "result.json").is_file(),
            "candidate_count": candidate_count,
            "verdict_count": verdict_count,
            "round_closed": paths["round_result"].is_file(),
            "refinement_proposed": paths["refinement"].is_file(),
        },
        "paths": {name: str(path) for name, path in paths.items()},
    }


def scan(repo: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    artifact_path = _resolve(repo, manifest["inputs"]["codeql_artifact"])
    artifact = _json(artifact_path)
    semantic_binding = manifest["inputs"].get("semantic_review")
    if semantic_binding is None:
        raise ValueError("round scan requires an independent semantic review binding")
    semantic_path = _resolve(repo, semantic_binding)
    semantic = _json(semantic_path)
    Draft202012Validator(
        _json(repo / "schemas" / "semantic-review.schema.json")
    ).validate(semantic)
    if artifact.get("status") != "preflight_passed":
        raise ValueError("round scan requires a preflight_passed CodeQL artifact")
    if (
        semantic_scan_admission(semantic) is None
        or semantic["pattern_id"] != artifact["pattern_id"]
        or semantic["artifact_version"] != artifact["artifact_version"]
        or semantic["artifact_sha256"] != sha256_file(artifact_path)
    ):
        raise ValueError("round scan semantic review does not admit the bound artifact")
    pack_dir, _ = materialize(repo, artifact_path, repo / "codeql" / "generated")
    codeql = yaml.safe_load((repo / "config" / "codeql.yaml").read_text(encoding="utf-8"))
    database = repo / codeql["database"]["path"]
    if not database.is_dir():
        raise FileNotFoundError(f"pinned CodeQL database is missing: {database}")
    result = verify_pack(repo, pack_dir, database=database, sarif_output=paths["sarif"])
    if not result["gate"]["scanned"]:
        raise RuntimeError("CodeQL scan gate failed")
    return result


def normalize(repo: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    if not paths["sarif"].is_file():
        raise FileNotFoundError("scan SARIF is missing")
    written = normalize_sarif(
        paths["sarif"], manifest["campaign_id"], manifest["pattern_id"], paths["candidate_dir"]
    )
    return {"candidate_count": len(written), "candidate_dir": str(paths["candidate_dir"])}


def plan_validation(
    repo: Path,
    manifest_path: Path,
    max_jobs: int,
    dry_run: bool,
    split_manifest: Path,
) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    pattern = _resolve(repo, manifest["inputs"]["pattern_ir"])
    rule_plan = _resolve(repo, manifest["inputs"]["rule_plan"])
    contexts = [_resolve(repo, binding) for binding in manifest["inputs"]["contexts"]]
    candidates = sorted(paths["candidate_dir"].glob("CANDIDATE-*.json"))
    attempted = completed = skipped = 0
    for candidate in candidates:
        for sanitizer in ("kasan", "kcsan"):
            if attempted >= max_jobs:
                break
            output = paths["job_root"] / candidate.stem / f"{sanitizer}.json"
            if output.is_file() and not dry_run:
                skipped += 1
                continue
            profile = repo / "config" / f"validation-{sanitizer}.json"
            inputs = [
                candidate,
                pattern,
                rule_plan,
                *contexts,
                repo / "config" / "runtime-harness.yaml",
                repo / "config" / "validation-adapters.yaml",
                profile,
            ]
            attempted += 1
            code = run_job(
                "reachability-planner",
                repo,
                inputs,
                output,
                dry_run,
                split_manifest,
            )
            if code:
                raise RuntimeError(f"reachability planner failed for {candidate.stem}/{sanitizer}")
            completed += 1
        if attempted >= max_jobs:
            break
    return {
        "candidate_count": len(candidates),
        "attempted": attempted,
        "completed": completed,
        "skipped": skipped,
        "dry_run": dry_run,
    }


def validate_runtime(repo: Path, manifest_path: Path, sanitizer: str, payload_size: int) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    return run_dispatch(
        repo,
        sanitizer,
        paths["validation_root"] / sanitizer,
        payload_size,
        paths["job_root"],
    )


def adjudicate(
    repo: Path,
    manifest_path: Path,
    max_jobs: int,
    dry_run: bool,
) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    pattern = _resolve(repo, manifest["inputs"]["pattern_ir"])
    rule_plan = _resolve(repo, manifest["inputs"]["rule_plan"])
    codeql = yaml.safe_load((repo / "config" / "codeql.yaml").read_text(encoding="utf-8"))
    source_root = repo / codeql["database"]["source_root"]
    if not source_root.is_dir():
        raise FileNotFoundError(f"vanilla v7.3 source is missing: {source_root}")
    bundles = build_bundles(
        paths["candidate_dir"],
        pattern,
        rule_plan,
        source_root,
        paths["validation_root"],
        paths["bundle_dir"],
    )
    attempted = completed = skipped = 0
    for bundle in bundles:
        if attempted >= max_jobs:
            break
        output = paths["verdict_dir"] / bundle.name
        if output.is_file() and not dry_run:
            skipped += 1
            continue
        attempted += 1
        code = run_job("adjudicator", repo, [bundle], output, dry_run)
        if code:
            raise RuntimeError(f"adjudicator failed for {bundle.stem}")
        completed += 1
    return {
        "bundle_count": len(bundles),
        "attempted": attempted,
        "completed": completed,
        "skipped": skipped,
        "dry_run": dry_run,
    }


def close_round(repo: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    return build_round_result(
        manifest["pattern_id"],
        manifest["round"],
        paths["candidate_dir"],
        paths["validation_root"],
        paths["verdict_dir"],
        paths["round_result"],
    )


def refine(
    repo: Path,
    manifest_path: Path,
    split_manifest: Path,
    dry_run: bool,
) -> dict[str, Any]:
    manifest = _json(manifest_path)
    paths = _paths(repo, manifest_path, manifest)
    if not paths["round_result"].is_file():
        raise FileNotFoundError("round result is missing")
    round_result = _json(paths["round_result"])
    if round_result["status"] != "complete":
        raise ValueError("only a complete round may be refined")
    pattern = _resolve(repo, manifest["inputs"]["pattern_ir"])
    bundles = sorted(paths["bundle_dir"].glob("CANDIDATE-*.json"))
    verdicts = sorted(paths["verdict_dir"].glob("CANDIDATE-*.json"))
    inputs = [pattern, paths["round_result"], *bundles, *verdicts, repo / "config" / "fp-circuit-breaker.yaml"]
    code = run_job(
        "refiner",
        repo,
        inputs,
        paths["refinement"],
        dry_run,
        split_manifest,
    )
    if code:
        raise RuntimeError("refiner failed")
    return {"output": str(paths["refinement"]), "dry_run": dry_run}


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute one independently versioned pattern round.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--campaign-id", required=True)
    init.add_argument("--round", type=int, required=True)
    init.add_argument("--pattern-ir", type=Path, required=True)
    init.add_argument("--rule-plan", type=Path, required=True)
    init.add_argument("--codeql-artifact", type=Path, required=True)
    init.add_argument("--semantic-review", type=Path)
    init.add_argument("--context", type=Path, action="append", default=[])
    for name in ("status", "scan", "normalize", "close"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
    plan = sub.add_parser("plan-validation")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--split-manifest", type=Path, required=True)
    plan.add_argument("--max-jobs", type=int, default=2)
    plan.add_argument("--dry-run", action="store_true")
    runtime = sub.add_parser("validate-runtime")
    runtime.add_argument("--manifest", type=Path, required=True)
    runtime.add_argument("--sanitizer", choices=("kasan", "kcsan"), required=True)
    runtime.add_argument("--payload-size", type=int, default=65536)
    adj = sub.add_parser("adjudicate")
    adj.add_argument("--manifest", type=Path, required=True)
    adj.add_argument("--max-jobs", type=int, default=1)
    adj.add_argument("--dry-run", action="store_true")
    ref = sub.add_parser("refine")
    ref.add_argument("--manifest", type=Path, required=True)
    ref.add_argument("--split-manifest", type=Path, required=True)
    ref.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    if args.command == "init":
        path, manifest = init_round(
            repo,
            args.campaign_id,
            args.round,
            args.pattern_ir.resolve(),
            args.rule_plan.resolve(),
            args.codeql_artifact.resolve(),
            [path.resolve() for path in args.context],
            args.semantic_review.resolve() if args.semantic_review else None,
        )
        result = {"manifest": str(path), **manifest}
    else:
        manifest_path = args.manifest.resolve()
        if args.command == "status":
            result = round_status(repo, manifest_path)
        elif args.command == "scan":
            result = scan(repo, manifest_path)
        elif args.command == "normalize":
            result = normalize(repo, manifest_path)
        elif args.command == "plan-validation":
            result = plan_validation(repo, manifest_path, args.max_jobs, args.dry_run, args.split_manifest.resolve())
        elif args.command == "validate-runtime":
            result = validate_runtime(repo, manifest_path, args.sanitizer, args.payload_size)
        elif args.command == "adjudicate":
            result = adjudicate(repo, manifest_path, args.max_jobs, args.dry_run)
        elif args.command == "close":
            result = close_round(repo, manifest_path)
        elif args.command == "refine":
            result = refine(repo, manifest_path, args.split_manifest.resolve(), args.dry_run)
        else:
            raise AssertionError(args.command)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
