import json
from pathlib import Path

import pytest

from compare_method.access_control import PartitionAccessError, enforce_role_partition_access
from compare_method.dataset_split import partition_map, public_view, split_cases


def _case(index: int, implementation: str = "KNFSD", group: str | None = None) -> dict:
    return {
        "case_id": f"CASE-{implementation}-CVE-20{index:02d}-{1000 + index}-RC01",
        "case_group_id": group or f"GROUP-{implementation}-{index}",
        "source_implementation": implementation,
        "identifier": {"cve_id": f"CVE-20{index:02d}-{1000 + index}"},
        "facts": {
            "protocol_versions_raw": ["NFSv4.1" if index % 2 else "NFSv3"],
            "root_cause_claims": ["use-after-free" if index % 3 else "out-of-bounds"],
            "published_or_commit_dates": [f"20{index:02d}-01-01"],
        },
    }


def test_split_is_exact_deterministic_and_keeps_groups_together() -> None:
    cases = [_case(index) for index in range(20)]
    cases += [_case(90, group="GROUP-KNFSD-MULTI"), _case(91, group="GROUP-KNFSD-MULTI")]
    cases += [_case(92, "GANESHA")]
    config = {
        "unit": "root_cause_group",
        "seed": 730015,
        "development": 0.70,
        "validation": 0.15,
        "sealed_holdout": 0.15,
    }
    first = split_cases(cases, config)
    second = split_cases(reversed(cases), config)
    assert first == second
    assert first["group_counts"] == {"development": 15, "validation": 3, "sealed_holdout": 3}
    assignments = partition_map(first)
    assert assignments[cases[-3]["case_id"]] == assignments[cases[-2]["case_id"]]
    assert assignments[cases[-1]["case_id"]] == "external_analogue"


def test_public_view_hides_validation_and_holdout_ids() -> None:
    config = {
        "unit": "root_cause_group",
        "seed": 1,
        "development": 0.70,
        "validation": 0.15,
        "sealed_holdout": 0.15,
    }
    private = split_cases([_case(index) for index in range(20)], config)
    public = public_view(private, "a" * 64)
    rendered = json.dumps(public)
    assignments = partition_map(private)
    for case_id, partition in assignments.items():
        if partition in {"validation", "sealed_holdout"}:
            assert case_id not in rendered


def test_generator_rejects_non_development_case(tmp_path: Path) -> None:
    private = {
        "assignments": [
            {
                "case_group_id": "GROUP-KNFSD-1",
                "case_ids": ["CASE-KNFSD-CVE-2099-9999-RC01"],
                "strata": ["nfs4", "other", "2099"],
                "partition": "sealed_holdout",
            }
        ],
        "external_analogue_case_ids": [],
    }
    split = tmp_path / "split.json"
    split.write_text(json.dumps(private), encoding="utf-8")
    evidence = tmp_path / "pattern.json"
    evidence.write_text(
        json.dumps({"member_cases": ["CASE-KNFSD-CVE-2099-9999-RC01"]}),
        encoding="utf-8",
    )
    with pytest.raises(PartitionAccessError, match="sealed_holdout"):
        enforce_role_partition_access("refiner", [evidence], split)


def test_generator_requires_split_manifest(tmp_path: Path) -> None:
    evidence = tmp_path / "pattern.json"
    evidence.write_text("{}", encoding="utf-8")
    with pytest.raises(PartitionAccessError, match="requires --split-manifest"):
        enforce_role_partition_access("rule-planner", [evidence], None)
