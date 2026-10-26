from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any

from .common import repo_root, sha256_file, write_json


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_round_result(
    pattern_id: str,
    round_number: int,
    candidate_dir: Path,
    validation_root: Path,
    verdict_dir: Path,
    output: Path,
) -> dict[str, Any]:
    candidates = {
        _json(path)["candidate_id"]: path
        for path in sorted(candidate_dir.glob("CANDIDATE-*.json"))
        if not path.name.endswith(".audit.json")
    }
    verdicts = {
        _json(path)["candidate_id"]: path
        for path in sorted(verdict_dir.glob("CANDIDATE-*.json"))
        if not path.name.endswith(".audit.json")
    }
    runtime: dict[str, dict[str, Any]] = {}
    runtime_artifacts = {}
    for sanitizer in ("kasan", "kcsan"):
        path = validation_root / sanitizer / "result.json"
        if not path.is_file():
            continue
        report = _json(path)
        runtime_artifacts[sanitizer] = {"path": str(path), "sha256": sha256_file(path)}
        for result in report["results"]:
            runtime.setdefault(result["candidate_id"], {})[sanitizer] = result

    records = []
    for candidate_id, candidate_path in candidates.items():
        verdict_path = verdicts.get(candidate_id)
        verdict = _json(verdict_path) if verdict_path else None
        records.append(
            {
                "candidate_id": candidate_id,
                "candidate_path": str(candidate_path),
                "candidate_sha256": sha256_file(candidate_path),
                "runtime": runtime.get(candidate_id, {}),
                "verdict_path": str(verdict_path) if verdict_path else None,
                "verdict_sha256": sha256_file(verdict_path) if verdict_path else None,
                "final_label": verdict.get("final_label") if verdict else "missing_verdict",
            }
        )
    counts = collections.Counter(record["final_label"] for record in records)
    complete = len(verdicts) == len(candidates) and (
        not records
        or all(set(record["runtime"]) == {"kasan", "kcsan"} for record in records)
    )
    result = {
        "schema_version": "1.0.0",
        "pattern_id": pattern_id,
        "round": round_number,
        "status": "complete" if complete else "incomplete",
        "candidate_count": len(candidates),
        "verdict_count": len(verdicts),
        "label_counts": dict(sorted(counts.items())),
        "runtime_artifacts": runtime_artifacts,
        "candidates": records,
        "ruleset_action": (
            "refine_before_next_round"
            if counts.get("confirmed_fp", 0)
            else "run_regression_and_holdout_before_promotion"
            if not records
            else "evaluate_promotion"
        ),
        "promotion_ready": False if counts.get("confirmed_fp", 0) or not records else None,
    }
    write_json(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate one pattern's completed round.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--pattern-id", required=True)
    parser.add_argument("--round", type=int, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--validation-root", type=Path, required=True)
    parser.add_argument("--verdict-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_round_result(
        args.pattern_id,
        args.round,
        args.candidate_dir.resolve(),
        args.validation_root.resolve(),
        args.verdict_dir.resolve(),
        args.output.resolve(),
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
