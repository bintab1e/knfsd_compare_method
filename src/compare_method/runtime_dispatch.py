from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .common import repo_root, sha256_file, write_json
from .runtime_probe import REQUESTS, run_probe


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _jobs(repo: Path, sanitizer: str, jobs_root: Path | None = None) -> list[tuple[Path, dict[str, Any]]]:
    root = jobs_root or repo / "validation" / "jobs"
    return [(path, _json(path)) for path in sorted(root.glob(f"CANDIDATE-*/{sanitizer}.json"))]


def _legacy_adapter(job: dict[str, Any]) -> dict[str, Any]:
    function = next((name for name in REQUESTS if name in job.get("target_functions", [])), None)
    if function:
        return {
            "kind": "rpc_template",
            "adapter_id": function,
            "source_path": None,
            "symbol": function,
            "program_path": None,
            "reason": "inferred from legacy validation job",
        }
    return {
        "kind": "unavailable",
        "adapter_id": None,
        "source_path": None,
        "symbol": None,
        "program_path": None,
        "reason": "legacy job has no supported exact RPC template",
    }


def _safe_source_path(value: str | None) -> bool:
    if value is None:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and value.startswith(("fs/", "net/"))


def dispatch_plan(
    repo: Path, sanitizer: str, jobs_root: Path | None = None
) -> dict[str, Any]:
    config_path = repo / "config" / "validation-adapters.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    stage1 = config["syzkaller_stage1"]
    stage1_checks = {
        "repository": (repo / stage1["repository"]).is_dir(),
        "python": (repo / stage1["python"]).is_file(),
        "config": (repo / stage1["config"]).is_file(),
    }
    items = []
    for path, job in _jobs(repo, sanitizer, jobs_root):
        adapter = job.get("validation_adapter") or _legacy_adapter(job)
        kind = adapter["kind"]
        reason = None
        if kind == "rpc_template":
            adapter_id = adapter.get("adapter_id")
            if adapter_id not in config["rpc_templates"] or adapter_id not in REQUESTS:
                status = "harness_gap"
                reason = f"unknown RPC template: {adapter_id}"
            elif config["rpc_templates"][adapter_id]["target_function"] not in job["target_functions"]:
                status = "harness_gap"
                reason = "RPC template target does not match validation target"
            else:
                status = "ready"
        elif kind == "syzkaller_stage1":
            if not _safe_source_path(adapter.get("source_path")):
                status = "harness_gap"
                reason = "syzkaller Stage 1 requires a safe kernel-relative source_path"
            elif not adapter.get("symbol") or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", adapter["symbol"]):
                status = "harness_gap"
                reason = "syzkaller Stage 1 requires one C symbol"
            elif not all(stage1_checks.values()):
                status = "harness_gap"
                reason = "syzkaller Stage 1 deployment is not configured"
            else:
                status = "ready"
        else:
            status = "harness_gap"
            reason = adapter.get("reason") or "no available validation adapter"
        items.append(
            {
                "candidate_id": job["candidate_id"],
                "job_path": str(path),
                "job_sha256": sha256_file(path),
                "adapter": adapter,
                "dispatch_status": status,
                "reason": reason,
            }
        )
    return {
        "schema_version": "1.0.0",
        "sanitizer": sanitizer,
        "kernel_ref": "v7.3",
        "adapter_config_sha256": sha256_file(config_path),
        "syzkaller_stage1_checks": stage1_checks,
        "jobs": items,
        "counts": {
            "ready": sum(item["dispatch_status"] == "ready" for item in items),
            "harness_gap": sum(item["dispatch_status"] == "harness_gap" for item in items),
        },
    }


def _run_stage1(repo: Path, sanitizer: str, item: dict[str, Any], output: Path) -> dict[str, Any]:
    config = yaml.safe_load((repo / "config" / "validation-adapters.yaml").read_text(encoding="utf-8"))
    stage1 = config["syzkaller_stage1"]
    adapter = item["adapter"]
    command = [
        str(repo / stage1["python"]),
        "-m",
        stage1["module"],
        "--config",
        str(repo / stage1["config"]),
        "submit",
        "--commit",
        stage1["kernel_commit"],
        "--path",
        adapter["source_path"],
        "--symbol",
        adapter["symbol"],
        "--policy",
        stage1["policies"][sanitizer],
    ]
    completed = subprocess.run(
        command,
        cwd=repo / stage1["repository"],
        text=True,
        capture_output=True,
        check=False,
    )
    result = {
        "candidate_id": item["candidate_id"],
        "adapter": "syzkaller_stage1",
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-8000:],
        "stderr": completed.stderr[-8000:],
        "terminal_label": "submitted" if completed.returncode == 0 else "harness_gap",
    }
    write_json(output / f"{item['candidate_id']}.stage1-submit.json", result)
    return result


def run_dispatch(
    repo: Path,
    sanitizer: str,
    output: Path,
    payload_size: int,
    jobs_root: Path | None = None,
) -> dict[str, Any]:
    plan = dispatch_plan(repo, sanitizer, jobs_root)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "dispatch-plan.json", plan)
    rpc = [
        item
        for item in plan["jobs"]
        if item["dispatch_status"] == "ready" and item["adapter"]["kind"] == "rpc_template"
    ]
    stage1 = [
        item
        for item in plan["jobs"]
        if item["dispatch_status"] == "ready" and item["adapter"]["kind"] == "syzkaller_stage1"
    ]
    details: dict[str, Any] = {
        "rpc_probe": None,
        "stage1_submissions": [],
        "harness_gaps": [item for item in plan["jobs"] if item["dispatch_status"] == "harness_gap"],
    }
    if rpc:
        # runtime_probe performs exact target-hit accounting and retains unsupported jobs as gaps.
        details["rpc_probe"] = run_probe(
            repo, sanitizer, output / "rpc", payload_size, jobs_root
        )
    for item in stage1:
        details["stage1_submissions"].append(_run_stage1(repo, sanitizer, item, output / "stage1"))
    normalized_results = []
    rpc_by_id = {
        result["candidate_id"]: result
        for result in (details["rpc_probe"] or {}).get("results", [])
    }
    stage1_by_id = {result["candidate_id"]: result for result in details["stage1_submissions"]}
    for item in plan["jobs"]:
        candidate_id = item["candidate_id"]
        if candidate_id in rpc_by_id:
            normalized_results.append(rpc_by_id[candidate_id])
        elif candidate_id in stage1_by_id:
            normalized_results.append(stage1_by_id[candidate_id])
        else:
            normalized_results.append(
                {
                    "candidate_id": candidate_id,
                    "job_path": item["job_path"],
                    "target_function": item["adapter"].get("symbol"),
                    "attempted_runs": 0,
                    "effective_target_reached_runs": 0,
                    "required_effective_runs": 0,
                    "sanitizer_signals": [],
                    "terminal_label": "harness_gap",
                    "reason": item["reason"],
                }
            )
    report = {
        "schema_version": "1.0.0",
        "sanitizer": sanitizer,
        "kernel_ref": "v7.3",
        "dispatch_plan_path": str(output / "dispatch-plan.json"),
        "results": normalized_results,
        "probe_hits": (details["rpc_probe"] or {}).get("probe_hits", {}),
        "transport": (details["rpc_probe"] or {}).get("transport"),
        "payload_size": (details["rpc_probe"] or {}).get("payload_size"),
        "dmesg_path": (details["rpc_probe"] or {}).get("dmesg_path"),
        "dmesg_sha256": (details["rpc_probe"] or {}).get("dmesg_sha256"),
        "trace_path": (details["rpc_probe"] or {}).get("trace_path"),
        "trace_sha256": (details["rpc_probe"] or {}).get("trace_sha256"),
        "details": details,
    }
    write_json(output / "result.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Dispatch validation jobs to exact RPC or syzkaller Stage 1 adapters.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--sanitizer", choices=("kasan", "kcsan"), required=True)
    parser.add_argument("--jobs-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--payload-size", type=int, default=65536)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    jobs_root = args.jobs_root.resolve() if args.jobs_root else None
    if args.run:
        if args.output is None:
            raise SystemExit("--output is required with --run")
        result = run_dispatch(repo, args.sanitizer, args.output.resolve(), args.payload_size, jobs_root)
    else:
        result = dispatch_plan(repo, args.sanitizer, jobs_root)
        if args.output:
            write_json(args.output.resolve(), result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
