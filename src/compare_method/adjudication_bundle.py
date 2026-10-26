from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .common import repo_root, sha256_file, write_json


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _snippet(source_root: Path, detection: dict[str, Any], radius: int = 24) -> dict[str, Any]:
    location = detection["location"]
    relative = Path(location["path"])
    source = source_root / relative
    line = int(location["start_line"])
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    first = max(1, line - radius)
    last = min(len(lines), line + radius)
    numbered = "\n".join(f"{number:6d}\t{lines[number - 1]}" for number in range(first, last + 1))
    return {
        "path": str(relative),
        "source_sha256": sha256_file(source),
        "candidate_line": line,
        "first_line": first,
        "last_line": last,
        "text": numbered,
    }


def _runtime_for_candidate(validation_root: Path, candidate_id: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for sanitizer in ("kasan", "kcsan"):
        result_path = validation_root / sanitizer / "result.json"
        if not result_path.is_file():
            evidence[sanitizer] = {"status": "not_run"}
            continue
        report = _json(result_path)
        result = next(
            (item for item in report.get("results", []) if item.get("candidate_id") == candidate_id),
            None,
        )
        evidence[sanitizer] = {
            "status": "present",
            "result_path": str(result_path),
            "result_sha256": sha256_file(result_path),
            "runtime": result,
            "probe_hits": report.get("probe_hits"),
            "transport": report.get("transport"),
            "payload_size": report.get("payload_size"),
            "dmesg_path": report.get("dmesg_path"),
            "dmesg_sha256": report.get("dmesg_sha256"),
            "trace_path": report.get("trace_path"),
            "trace_sha256": report.get("trace_sha256"),
        }
    return evidence


def build_bundles(
    candidate_dir: Path,
    pattern_ir: Path,
    rule_plan: Path,
    source_root: Path,
    validation_root: Path,
    output: Path,
) -> list[Path]:
    pattern = _json(pattern_ir)
    plan = _json(rule_plan)
    outputs = []
    output.mkdir(parents=True, exist_ok=True)
    for candidate_path in sorted(candidate_dir.glob("CANDIDATE-*.json")):
        candidate = _json(candidate_path)
        detections = candidate.get("detections", [])
        bundle = {
            "schema_version": "1.0.0",
            "candidate": candidate,
            "pattern_ir": pattern,
            "rule_plan": plan,
            "source_context": [
                _snippet(source_root, detection) for detection in detections
            ],
            "runtime_evidence": _runtime_for_candidate(
                validation_root, candidate["candidate_id"]
            ),
            "provenance": {
                "candidate_path": str(candidate_path),
                "candidate_sha256": sha256_file(candidate_path),
                "pattern_ir_path": str(pattern_ir),
                "pattern_ir_sha256": sha256_file(pattern_ir),
                "rule_plan_path": str(rule_plan),
                "rule_plan_sha256": sha256_file(rule_plan),
            },
        }
        destination = output / f"{candidate['candidate_id']}.json"
        write_json(destination, bundle)
        outputs.append(destination)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Build one evidence bundle per CodeQL candidate.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--pattern-ir", type=Path, required=True)
    parser.add_argument("--rule-plan", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--validation-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = build_bundles(
        args.candidate_dir.resolve(),
        args.pattern_ir.resolve(),
        args.rule_plan.resolve(),
        args.source_root.resolve(),
        args.validation_root.resolve(),
        args.output.resolve(),
    )
    print(json.dumps({"bundles": [str(path) for path in paths]}, indent=2))


if __name__ == "__main__":
    main()
