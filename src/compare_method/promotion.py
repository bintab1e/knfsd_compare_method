from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .common import repo_root, sha256_file, write_json


IGNORED_AS_FP = {
    "inconclusive",
    "unreached",
    "harness_gap",
    "no_signal",
    "no_signal_after_100",
    "insufficient_runs",
}


def _partition(evaluation: dict[str, Any], name: str) -> dict[str, Any]:
    return evaluation.get("partitions", {}).get(name, {})


def _labels(evaluation: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        record
        for partition in evaluation.get("partitions", {}).values()
        for record in partition.get("records", [])
    ]


def _ids(evaluation: dict[str, Any], label: str) -> set[str]:
    return {
        str(record["candidate_id"])
        for record in _labels(evaluation)
        if record.get("final_label") == label
    }


def _known(partition: dict[str, Any]) -> tuple[int, int]:
    positives = set(map(str, partition.get("known_positive_ids", [])))
    detected = set(map(str, partition.get("detected_known_positive_ids", [])))
    return len(positives & detected), len(positives)


def _summary(evaluation: dict[str, Any]) -> dict[str, Any]:
    val_detected, val_total = _known(_partition(evaluation, "validation"))
    hold_detected, hold_total = _known(_partition(evaluation, "sealed_holdout"))
    return {
        "candidate_count": int(evaluation.get("candidate_count", 0)),
        "runtime_seconds": float(evaluation.get("runtime_seconds", 0.0)),
        "confirmed_tp": len(_ids(evaluation, "confirmed_tp")),
        "confirmed_fp": len(_ids(evaluation, "confirmed_fp")),
        "validation_known_positive_detected": val_detected,
        "validation_known_positive_total": val_total,
        "holdout_known_positive_detected": hold_detected,
        "holdout_known_positive_total": hold_total,
    }


def _growth(candidate: float, baseline: float) -> float | None:
    if baseline == 0:
        return None if candidate == 0 else float("inf")
    return round(candidate / baseline, 6)


def decide_promotion(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    promotion_policy: dict[str, Any],
    circuit_policy: dict[str, Any],
    *,
    milestone: bool,
    input_hashes: dict[str, str],
) -> dict[str, Any]:
    if baseline["pattern_id"] != candidate["pattern_id"]:
        raise ValueError("baseline and candidate pattern IDs differ")
    baseline_tp = _ids(baseline, "confirmed_tp")
    candidate_tp = _ids(candidate, "confirmed_tp")
    baseline_fp = _ids(baseline, "confirmed_fp")
    candidate_fp = _ids(candidate, "confirmed_fp")
    baseline_summary = _summary(baseline)
    candidate_summary = _summary(candidate)

    complete = bool(candidate.get("complete", False))
    preserves_tp = baseline_tp <= candidate_tp
    improves = bool(candidate_tp - baseline_tp) or len(candidate_fp) < len(baseline_fp)
    validation_ok = (
        candidate_summary["validation_known_positive_total"]
        == baseline_summary["validation_known_positive_total"]
        and candidate_summary["validation_known_positive_detected"]
        >= baseline_summary["validation_known_positive_detected"]
    )
    candidate_growth = _growth(
        candidate_summary["candidate_count"], baseline_summary["candidate_count"]
    )
    runtime_growth = _growth(
        candidate_summary["runtime_seconds"], baseline_summary["runtime_seconds"]
    )
    configured_limit = circuit_policy.get("candidate_flood_limit")
    candidate_limit = int(
        configured_limit
        if configured_limit is not None
        else max(30, baseline_summary["candidate_count"] * 2, baseline_summary["candidate_count"] + 50)
    )
    volume_ok = candidate_summary["candidate_count"] <= candidate_limit
    runtime_multiplier = float(promotion_policy.get("max_runtime_growth", 2.0))
    runtime_ok = (
        candidate_summary["runtime_seconds"] == 0
        or baseline_summary["runtime_seconds"] == 0
        or candidate_summary["runtime_seconds"] <= baseline_summary["runtime_seconds"] * runtime_multiplier
    )

    holdout_ok: bool | None = None
    if milestone:
        candidate_holdout = candidate_summary["holdout_known_positive_detected"]
        baseline_holdout = baseline_summary["holdout_known_positive_detected"]
        total = candidate_summary["holdout_known_positive_total"]
        holdout_ok = total > 0 and candidate_holdout >= baseline_holdout and candidate_holdout > 0

    records = _labels(candidate)
    adjudicated = sum(
        1
        for record in records
        if record.get("final_label") not in IGNORED_AS_FP | {"duplicate"}
    )
    minimum_met = adjudicated >= int(circuit_policy["minimum_adjudicated_samples"])
    no_improvement_rounds = int(candidate.get("no_improvement_rounds", 0))
    protections = set(map(str, candidate.get("protections", [])))
    protected = bool(protections & set(circuit_policy.get("protect_if", [])))

    if not volume_ok:
        circuit_state = "throttled"
    elif (
        no_improvement_rounds >= int(circuit_policy["no_improvement_rounds_before_quarantine"])
        and not protected
    ):
        circuit_state = "quarantined"
    elif candidate_fp and minimum_met and not improves:
        circuit_state = "refinement_required"
    else:
        circuit_state = "active"

    gates = {
        "complete_evidence": complete,
        "preserves_existing_confirmed_tp": preserves_tp,
        "new_tp_or_fewer_confirmed_fp": improves,
        "validation_does_not_regress": validation_ok,
        "candidate_volume_acceptable": volume_ok,
        "runtime_acceptable": runtime_ok,
        "sealed_holdout_passed": holdout_ok,
    }
    required_gates = [complete, preserves_tp, improves, validation_ok, volume_ok, runtime_ok]
    if milestone:
        required_gates.append(bool(holdout_ok))

    reasons = [name for name, passed in gates.items() if passed is False]
    if circuit_state == "throttled":
        decision = "throttle"
    elif circuit_state == "quarantined":
        decision = "quarantine"
    elif not complete:
        decision = "insufficient_evidence"
    elif all(required_gates):
        decision = "promote"
    elif candidate_fp:
        decision = "refine"
    else:
        decision = "keep_baseline"

    return {
        "schema_version": "1.0.0",
        "pattern_id": baseline["pattern_id"],
        "baseline_version": int(baseline["rule_version"]),
        "candidate_version": int(candidate["rule_version"]),
        "milestone_holdout_evaluation": milestone,
        "gates": gates,
        "metrics": {
            "baseline": baseline_summary,
            "candidate": candidate_summary,
            "candidate_growth": candidate_growth if candidate_growth != float("inf") else None,
            "runtime_growth": runtime_growth if runtime_growth != float("inf") else None,
            "adjudicated_samples": adjudicated,
        },
        "circuit_breaker": {
            "state": circuit_state,
            "candidate_limit": candidate_limit,
            "minimum_adjudicated_samples_met": minimum_met,
            "protected": protected,
            "no_improvement_rounds": no_improvement_rounds,
        },
        "decision": decision,
        "reasons": reasons,
        "input_hashes": input_hashes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate rule promotion and FP circuit-breaker policy.")
    parser.add_argument("--repo", type=Path, default=repo_root())
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--milestone", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    promotion_path = repo / "config" / "promotion-policy.yaml"
    circuit_path = repo / "config" / "fp-circuit-breaker.yaml"
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
    decision = decide_promotion(
        baseline,
        candidate,
        yaml.safe_load(promotion_path.read_text(encoding="utf-8")),
        yaml.safe_load(circuit_path.read_text(encoding="utf-8")),
        milestone=args.milestone,
        input_hashes={
            "baseline": sha256_file(args.baseline),
            "candidate": sha256_file(args.candidate),
            "promotion_policy": sha256_file(promotion_path),
            "circuit_breaker_policy": sha256_file(circuit_path),
        },
    )
    schema = json.loads((repo / "schemas" / "promotion-decision.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(decision)
    write_json(args.output.resolve(), decision)
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
