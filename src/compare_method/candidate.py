from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .common import canonical_json, repo_root, sha256_bytes, sha256_file, write_json


def _primary_location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations") or []
    physical = (locations[0] if locations else {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    return {
        "path": artifact.get("uri"),
        "start_line": region.get("startLine"),
        "start_column": region.get("startColumn"),
        "end_line": region.get("endLine"),
        "end_column": region.get("endColumn"),
    }


def normalize_sarif(
    sarif_path: Path,
    campaign_id: str,
    pattern_id: str,
    output_dir: Path,
) -> list[Path]:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    sarif_hash = sha256_file(sarif_path)
    grouped: dict[str, dict[str, Any]] = {}

    for run_index, run in enumerate(sarif.get("runs", [])):
        for result_index, result in enumerate(run.get("results", [])):
            location = _primary_location(result)
            identity = {
                "pattern_id": pattern_id,
                "rule_id": result.get("ruleId"),
                "path": location["path"],
                "start_line": location["start_line"],
                "message": (result.get("message") or {}).get("text"),
            }
            fingerprint = sha256_bytes(canonical_json(identity))
            candidate = grouped.setdefault(
                fingerprint,
                {
                    "candidate_id": f"CANDIDATE-{fingerprint[:16].upper()}",
                    "campaign_id": campaign_id,
                    "pattern_id": pattern_id,
                    "fingerprint": f"sha256:{fingerprint}",
                    "detections": [],
                    "status": "new",
                    "provenance": {
                        "sarif_path": str(sarif_path),
                        "sarif_sha256": sarif_hash,
                    },
                },
            )
            candidate["detections"].append(
                {
                    "rule_id": result.get("ruleId"),
                    "level": result.get("level"),
                    "message": (result.get("message") or {}).get("text"),
                    "location": location,
                    "run_index": run_index,
                    "result_index": result_index,
                    "partial_fingerprints": result.get("partialFingerprints", {}),
                }
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fingerprint in sorted(grouped):
        candidate = grouped[fingerprint]
        path = output_dir / f"{candidate['candidate_id']}.json"
        write_json(path, candidate)
        written.append(path)

    index_path = output_dir / "candidates.jsonl"
    index_path.write_text(
        "".join(
            json.dumps(grouped[key], ensure_ascii=False, sort_keys=True) + "\n"
            for key in sorted(grouped)
        ),
        encoding="utf-8",
    )
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize CodeQL SARIF results into candidates.")
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--pattern-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=repo_root())
    args = parser.parse_args()
    paths = normalize_sarif(
        args.sarif.resolve(),
        args.campaign_id,
        args.pattern_id,
        args.output_dir.resolve(),
    )
    print(json.dumps({"candidate_count": len(paths), "output_dir": str(args.output_dir.resolve())}))


if __name__ == "__main__":
    main()
