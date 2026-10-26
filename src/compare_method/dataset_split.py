from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

import yaml

from .common import canonical_json, repo_root, sha256_bytes, sha256_file, write_json


PARTITIONS = ("development", "validation", "sealed_holdout")
CASE_ID_RE = re.compile(r"^CASE-[A-Z0-9]+-")


def _stable_digest(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()


def _protocol_bucket(case: dict[str, Any]) -> str:
    text = " ".join(case["facts"].get("protocol_versions_raw", [])).lower()
    buckets = []
    for needle, name in (
        ("v4.2", "nfs4.2"),
        ("4.2", "nfs4.2"),
        ("v4.1", "nfs4.1"),
        ("4.1", "nfs4.1"),
        ("v4", "nfs4"),
        ("nfsv4", "nfs4"),
        ("v3", "nfs3"),
        ("nfsv3", "nfs3"),
        ("v2", "nfs2"),
        ("nfsv2", "nfs2"),
        ("rpc", "rpc"),
    ):
        if needle in text and name not in buckets:
            buckets.append(name)
    return "+".join(buckets) if buckets else "unspecified"


def _root_cause_bucket(case: dict[str, Any]) -> str:
    text = " ".join(case["facts"].get("root_cause_claims", [])).lower()
    categories = (
        (("use-after-free", "use after free", "uaf", "해제 후"), "use_after_free"),
        (("out-of-bounds", "out of bounds", "oob", "경계", "범위 밖"), "out_of_bounds"),
        (("overflow", "underflow", "오버플로", "언더플로"), "integer_overflow"),
        (("race", "경쟁", "동시성"), "race"),
        (("deadlock", "교착"), "deadlock"),
        (("null", "널 포인터"), "null_dereference"),
        (("uninitialized", "초기화되지"), "uninitialized"),
        (("information leak", "info leak", "정보 노출"), "information_leak"),
        (("permission", "authorization", "권한", "인증 우회"), "authorization"),
        (("double free", "이중 해제"), "double_free"),
        (("resource", "memory leak", "denial", "dos", "고갈", "누수"), "resource_exhaustion"),
        (("infinite loop", "무한 루프"), "infinite_loop"),
    )
    for needles, category in categories:
        if any(needle in text for needle in needles):
            return category
    return "other"


def _publication_year(case: dict[str, Any]) -> str:
    cve = case.get("identifier", {}).get("cve_id") or ""
    match = re.match(r"CVE-(\d{4})-", cve)
    if match:
        return match.group(1)
    for value in case["facts"].get("published_or_commit_dates", []):
        match = re.search(r"(?:19|20)\d{2}", value)
        if match:
            return match.group(0)
    return "unknown"


def _targets(total: int, ratios: dict[str, float]) -> dict[str, int]:
    raw = {name: total * ratios[name] for name in PARTITIONS}
    result = {name: math.floor(raw[name]) for name in PARTITIONS}
    remainder = total - sum(result.values())
    order = sorted(
        PARTITIONS,
        key=lambda name: (raw[name] - result[name], ratios[name], name),
        reverse=True,
    )
    for name in order[:remainder]:
        result[name] += 1
    return result


def _interleave_strata(groups: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], deque[dict[str, Any]]] = {}
    staged: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for group in groups:
        staged[tuple(group["strata"])].append(group)
    for key, values in staged.items():
        values.sort(key=lambda item: _stable_digest(seed, item["case_group_id"]))
        buckets[key] = deque(values)

    ordered: list[dict[str, Any]] = []
    keys = sorted(buckets, key=lambda key: _stable_digest(seed, "|".join(key)))
    while keys:
        next_keys = []
        for key in keys:
            ordered.append(buckets[key].popleft())
            if buckets[key]:
                next_keys.append(key)
        keys = next_keys
    return ordered


def split_cases(cases: Iterable[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    ratios = {name: float(config[name]) for name in PARTITIONS}
    if abs(sum(ratios.values()) - 1.0) > 1e-9:
        raise ValueError("dataset split ratios must sum to 1.0")
    seed = int(config["seed"])
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    external = []
    for case in cases:
        if case["source_implementation"] == "KNFSD":
            by_group[case["case_group_id"]].append(case)
        else:
            external.append(case["case_id"])

    groups = []
    for group_id, members in sorted(by_group.items()):
        first = sorted(members, key=lambda item: item["case_id"])[0]
        groups.append(
            {
                "case_group_id": group_id,
                "case_ids": sorted(item["case_id"] for item in members),
                "strata": [
                    _protocol_bucket(first),
                    _root_cause_bucket(first),
                    _publication_year(first),
                ],
            }
        )

    target_counts = _targets(len(groups), ratios)
    remaining = target_counts.copy()
    assignments = []
    for index, group in enumerate(_interleave_strata(groups, seed)):
        available = [name for name in PARTITIONS if remaining[name] > 0]
        if not available:
            raise AssertionError("split quota exhausted before all groups were assigned")
        partition = max(
            available,
            key=lambda name: (
                remaining[name] / max(target_counts[name], 1),
                _stable_digest(seed + index, f"{group['case_group_id']}:{name}"),
            ),
        )
        remaining[partition] -= 1
        assignments.append(group | {"partition": partition})

    assignments.sort(key=lambda item: item["case_group_id"])
    case_counts = {
        name: sum(len(item["case_ids"]) for item in assignments if item["partition"] == name)
        for name in PARTITIONS
    }
    return {
        "schema_version": "1.0.0",
        "unit": config["unit"],
        "seed": seed,
        "ratios": ratios,
        "target_implementation": "KNFSD",
        "group_counts": target_counts,
        "case_counts": case_counts,
        "assignments": assignments,
        "external_analogue_case_ids": sorted(external),
    }


def _commitment(partition: str, assignments: list[dict[str, Any]]) -> str:
    payload = [
        {"case_group_id": item["case_group_id"], "case_ids": item["case_ids"]}
        for item in assignments
        if item["partition"] == partition
    ]
    return "sha256:" + sha256_bytes(canonical_json(payload))


def public_view(private: dict[str, Any], private_sha256: str) -> dict[str, Any]:
    development_ids = sorted(
        case_id
        for item in private["assignments"]
        if item["partition"] == "development"
        for case_id in item["case_ids"]
    )
    hidden = {
        name: {
            "group_count": private["group_counts"][name],
            "case_count": private["case_counts"][name],
            "commitment": _commitment(name, private["assignments"]),
        }
        for name in ("validation", "sealed_holdout")
    }
    return {
        "schema_version": "1.0.0",
        "unit": private["unit"],
        "seed": private["seed"],
        "ratios": private["ratios"],
        "target_implementation": private["target_implementation"],
        "development": {
            "group_count": private["group_counts"]["development"],
            "case_count": private["case_counts"]["development"],
            "case_ids": development_ids,
        },
        "external_analogues": {
            "case_count": len(private["external_analogue_case_ids"]),
            "case_ids": private["external_analogue_case_ids"],
        },
        "validation": hidden["validation"],
        "sealed_holdout": hidden["sealed_holdout"],
        "private_manifest_sha256": private_sha256,
        "feedback_policy": {
            "validation_visible_to_generator_or_refiner": False,
            "sealed_holdout_feedback_allowed": False,
        },
    }


def build_split(repo: Path, private_path: Path, public_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    config_path = repo / "config" / "dataset-split.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    case_paths = sorted((repo / "data" / "cases").glob("*.json"))
    cases = [json.loads(path.read_text(encoding="utf-8")) for path in case_paths]
    private = split_cases(cases, config)
    private["source"] = {
        "case_count": len(cases),
        "case_set_sha256": sha256_bytes(
            canonical_json(
                [{"path": path.name, "sha256": sha256_file(path)} for path in case_paths]
            )
        ),
        "config_sha256": sha256_file(config_path),
    }
    write_json(private_path, private)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public = public_view(private, sha256_file(private_path))
    write_json(public_path, public)
    return private, public


def partition_map(private: dict[str, Any]) -> dict[str, str]:
    result = {}
    for item in private["assignments"]:
        for case_id in item["case_ids"]:
            result[case_id] = item["partition"]
    for case_id in private["external_analogue_case_ids"]:
        result[case_id] = "external_analogue"
    return result


def case_ids_in_value(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            found.update(case_ids_in_value(key))
            found.update(case_ids_in_value(child))
    elif isinstance(value, list):
        for child in value:
            found.update(case_ids_in_value(child))
    elif isinstance(value, str):
        for token in re.findall(r"CASE-[A-Z0-9]+-(?:CVE-[0-9]{4}-[0-9]{4,7}|COMMIT-[A-F0-9]{7,64}|UNRESOLVED-[A-F0-9]{12})-RC[0-9]{2}", value):
            if CASE_ID_RE.match(token):
                found.add(token)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Create the deterministic KNFSD development/validation/holdout split.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument(
        "--private-output",
        type=Path,
        default=Path("campaigns/_control/dataset-split.private.json"),
    )
    parser.add_argument(
        "--public-output",
        type=Path,
        default=Path("data/generated/dataset-split.public.json"),
    )
    args = parser.parse_args()
    repo = args.repo.resolve()
    private_path = args.private_output if args.private_output.is_absolute() else repo / args.private_output
    public_path = args.public_output if args.public_output.is_absolute() else repo / args.public_output
    private, public = build_split(repo, private_path, public_path)
    print(
        json.dumps(
            {
                "private_manifest": str(private_path),
                "public_manifest": str(public_path),
                "knfsd_case_counts": private["case_counts"],
                "external_analogue_cases": len(private["external_analogue_case_ids"]),
                "validation_commitment": public["validation"]["commitment"],
                "sealed_holdout_commitment": public["sealed_holdout"]["commitment"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
