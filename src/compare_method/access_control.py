from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .dataset_split import case_ids_in_value, partition_map


GENERATOR_OR_REFINER_ROLES = {
    "pattern-clusterer",
    "pattern-reviewer",
    "rule-planner",
    "codeql-author",
    "codeql-reviewer",
    "refiner",
}


class PartitionAccessError(ValueError):
    pass


def _load_input(path: Path) -> Any:
    raw = path.read_bytes()
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode("utf-8", errors="replace")


def enforce_role_partition_access(
    role: str, input_paths: list[Path], split_manifest: Path | None
) -> dict[str, str]:
    if role not in GENERATOR_OR_REFINER_ROLES:
        return {}
    if split_manifest is None:
        raise PartitionAccessError(
            f"{role} requires --split-manifest so Validation and Sealed Holdout inputs cannot leak"
        )
    private = json.loads(split_manifest.read_text(encoding="utf-8"))
    assignments = partition_map(private)
    seen: dict[str, str] = {}
    for path in input_paths:
        for case_id in case_ids_in_value(_load_input(path)):
            partition = assignments.get(case_id, "unknown")
            seen[case_id] = partition
            if partition in {"validation", "sealed_holdout"}:
                raise PartitionAccessError(
                    f"{role} may not consume {partition} case {case_id} from {path}"
                )
            if partition == "unknown" and case_id.startswith("CASE-KNFSD-"):
                raise PartitionAccessError(
                    f"{role} saw unassigned KNFSD case {case_id}; rebuild or select the correct split manifest"
                )
    return seen
